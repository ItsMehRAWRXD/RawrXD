#!/usr/bin/env pwsh
#==============================================================================
# RawrXD Sovereign Inferencer - Telemetry Collection Pipeline
# Phase G.1 Batch 1/5: Real-time Metrics Ingestion
#==============================================================================
# Collects real-time metrics from RawrXD runtime via named pipes and logs
#==============================================================================

[CmdletBinding()]
param(
    [Parameter()]
    [string]$PipeName = "RawrXD-Telemetry",

    [Parameter()]
    [int]$Port = 9999,

    [Parameter()]
    [string]$OutputPath = ".\telemetry_data",

    [Parameter()]
    [int]$BufferSize = 4096,

    [Parameter()]
    [switch]$UseNetwork,

    [Parameter()]
    [switch]$Daemon
)

#==============================================================================
# Telemetry Configuration
#==============================================================================

$script:TelemetryConfig = @{
    Version = "1.0.0"
    Metrics = @(
        @{ Name = "TPS"; Unit = "tokens/sec"; Threshold = 30; Type = "performance" }
        @{ Name = "TTFT"; Unit = "ms"; Threshold = 50; Type = "performance" }
        @{ Name = "Latency"; Unit = "ms"; Threshold = 100; Type = "performance" }
        @{ Name = "MemoryUsage"; Unit = "MB"; Threshold = 8192; Type = "resource" }
        @{ Name = "GPUUtilization"; Unit = "percent"; Threshold = 95; Type = "resource" }
        @{ Name = "HotpatchStatus"; Unit = "enum"; Threshold = 0; Type = "governance" }
        @{ Name = "SIS_Score"; Unit = "points"; Threshold = 85; Type = "governance" }
    )
    FlushIntervalSeconds = 5
    MaxBufferSize = 10000
}

#==============================================================================
# Telemetry Collector Classes
#==============================================================================

class TelemetryCollector {
    [string]$PipeName
    [int]$Port
    [string]$OutputPath
    [int]$BufferSize
    [bool]$UseNetwork
    [System.Collections.ArrayList]$Buffer
    [hashtable]$Stats
    [System.Net.Sockets.TcpListener]$TcpListener
    [System.IO.Pipes.NamedPipeServerStream]$PipeServer
    [bool]$IsRunning

    TelemetryCollector([string]$pipe, [int]$port, [string]$output, 
                       [int]$bufSize, [bool]$network) {
        $this.PipeName = $pipe
        $this.Port = $port
        $this.OutputPath = $output
        $this.BufferSize = $bufSize
        $this.UseNetwork = $network
        $this.Buffer = @()
        $this.Stats = @{
            TotalMetrics = 0
            StartTime = Get-Date
            LastFlush = Get-Date
        }
        $this.IsRunning = $false
    }

    [void] Initialize() {
        Write-Host "=== Initializing Telemetry Collector ===" -ForegroundColor Cyan
        
        New-Item -ItemType Directory -Force -Path $this.OutputPath | Out-Null
        
        if ($this.UseNetwork) {
            $this.TcpListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $this.Port)
            $this.TcpListener.Start()
            Write-Host "✓ TCP listener started on port $($this.Port)" -ForegroundColor Green
        }
        else {
            $this.PipeServer = [System.IO.Pipes.NamedPipeServerStream]::new(
                $this.PipeName, 
                [System.IO.Pipes.PipeDirection]::In,
                1,
                [System.IO.Pipes.PipeTransmissionMode]::Message,
                [System.IO.Pipes.PipeOptions]::Asynchronous,
                $this.BufferSize,
                $this.BufferSize
            )
            Write-Host "✓ Named pipe server started: \\$($this.PipeName)" -ForegroundColor Green
        }

        # Initialize stats file
        $statsPath = Join-Path $this.OutputPath "collector_stats.json"
        $this.Stats | ConvertTo-Json | Out-File $statsPath
        
        Write-Host "✓ Output directory: $($this.OutputPath)" -ForegroundColor Green
    }

    [void] StartCollection() {
        $this.IsRunning = $true
        Write-Host "`n=== Starting Telemetry Collection ===" -ForegroundColor Cyan
        
        if ($this.UseNetwork) {
            $this.StartNetworkCollection()
        }
        else {
            $this.StartPipeCollection()
        }
    }

    [void] StartNetworkCollection() {
        Write-Host "Listening for TCP connections on port $($this.Port)..." -ForegroundColor Yellow
        
        while ($this.IsRunning) {
            try {
                $client = $this.TcpListener.AcceptTcpClient()
                $stream = $client.GetStream()
                $reader = [System.IO.StreamReader]::new($stream)
                
                Write-Host "Client connected from $($client.Client.RemoteEndPoint)" -ForegroundColor Green
                
                while ($client.Connected -and $this.IsRunning) {
                    $line = $reader.ReadLine()
                    if ($line) {
                        $this.ProcessMetric($line)
                    }
                }
                
                $reader.Close()
                $client.Close()
            }
            catch {
                Write-Warning "Network error: $_"
            }
        }
    }

    [void] StartPipeCollection() {
        Write-Host "Waiting for pipe connection on \\$($this.PipeName)..." -ForegroundColor Yellow
        
        try {
            $this.PipeServer.WaitForConnection()
            Write-Host "✓ Client connected to pipe" -ForegroundColor Green
            
            $reader = [System.IO.StreamReader]::new($this.PipeServer)
            
            while ($this.IsRunning -and $this.PipeServer.IsConnected) {
                $line = $reader.ReadLine()
                if ($line) {
                    $this.ProcessMetric($line)
                }
                
                # Flush buffer periodically
                if ($this.Buffer.Count -ge $script:TelemetryConfig.FlushIntervalSeconds) {
                    $this.FlushBuffer()
                }
            }
            
            $reader.Close()
        }
        catch {
            Write-Error "Pipe error: $_"
        }
    }

    [void] ProcessMetric([string]$jsonData) {
        try {
            $metric = $jsonData | ConvertFrom-Json -AsHashtable
            
            # Validate metric structure
            if (-not $metric.Timestamp) {
                $metric.Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            }
            if (-not $metric.Source) {
                $metric.Source = "rawrxd-runtime"
            }
            
            # Add to buffer
            $this.Buffer.Add($metric)
            $this.Stats.TotalMetrics++
            
            # Check thresholds
            $this.CheckThresholds($metric)
            
            # Flush if buffer is full
            if ($this.Buffer.Count -ge $script:TelemetryConfig.MaxBufferSize) {
                $this.FlushBuffer()
            }
        }
        catch {
            Write-Warning "Failed to process metric: $_"
        }
    }

    [void] CheckThresholds([hashtable]$metric) {
        $config = $script:TelemetryConfig.Metrics | Where-Object { $_.Name -eq $metric.Name }
        if (-not $config) { return }
        
        $value = $metric.Value
        $threshold = $config.Threshold
        
        $breached = $false
        switch ($metric.Name) {
            "TPS" { if ($value -lt $threshold) { $breached = $true } }
            "TTFT" { if ($value -gt $threshold) { $breached = $true } }
            "Latency" { if ($value -gt $threshold) { $breached = $true } }
            "MemoryUsage" { if ($value -gt $threshold) { $breached = $true } }
            "GPUUtilization" { if ($value -gt $threshold) { $breached = $true } }
            "SIS_Score" { if ($value -lt $threshold) { $breached = $true } }
        }
        
        if ($breached) {
            $alert = @{
                Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
                Type = "Threshold_Breach"
                Metric = $metric.Name
                Value = $value
                Threshold = $threshold
                Severity = if ($metric.Name -eq "SIS_Score") { "Critical" } else { "Warning" }
            }
            
            $alertPath = Join-Path $this.OutputPath "alerts\$(Get-Date -Format 'yyyyMMdd_HHmmss')_alert.json"
            New-Item -ItemType Directory -Force -Path (Split-Path $alertPath) | Out-Null
            $alert | ConvertTo-Json | Out-File $alertPath
            
            Write-Warning "Threshold breach: $($metric.Name) = $value (threshold: $threshold)"
        }
    }

    [void] FlushBuffer() {
        if ($this.Buffer.Count -eq 0) { return }
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $filePath = Join-Path $this.OutputPath "metrics\$timestamp.jsonl"
        
        New-Item -ItemType Directory -Force -Path (Split-Path $filePath) | Out-Null
        
        foreach ($metric in $this.Buffer) {
            ($metric | ConvertTo-Json -Compress) | Out-File -Append -FilePath $filePath
        }
        
        Write-Host "Flushed $($this.Buffer.Count) metrics to $filePath" -ForegroundColor Gray
        $this.Buffer.Clear()
        $this.Stats.LastFlush = Get-Date
        
        # Update stats
        $statsPath = Join-Path $this.OutputPath "collector_stats.json"
        $this.Stats | ConvertTo-Json | Out-File $statsPath
    }

    [void] Stop() {
        Write-Host "`n=== Stopping Telemetry Collector ===" -ForegroundColor Cyan
        $this.IsRunning = $false
        
        $this.FlushBuffer()
        
        if ($this.TcpListener) {
            $this.TcpListener.Stop()
        }
        if ($this.PipeServer) {
            $this.PipeServer.Close()
        }
        
        Write-Host "✓ Collector stopped. Total metrics: $($this.Stats.TotalMetrics)" -ForegroundColor Green
    }

    [void] DisplayStatus() {
        $duration = (Get-Date) - $this.Stats.StartTime
        
        Write-Host "`n=== Collector Status ===" -ForegroundColor Cyan
        Write-Host "Running: $($this.IsRunning)" -ForegroundColor White
        Write-Host "Mode: $(if ($this.UseNetwork) { 'Network (TCP)' } else { 'Named Pipe' })" -ForegroundColor White
        Write-Host "Duration: $([math]::Round($duration.TotalMinutes, 2)) minutes" -ForegroundColor White
        Write-Host "Total Metrics: $($this.Stats.TotalMetrics)" -ForegroundColor White
        Write-Host "Buffer Size: $($this.Buffer.Count)" -ForegroundColor White
        Write-Host "Output: $($this.OutputPath)" -ForegroundColor White
    }
}

#==============================================================================
# Metric Emitter (for testing)
#==============================================================================

function Emit-TestMetrics {
    param(
        [string]$PipeName = "RawrXD-Telemetry",
        [int]$Port = 9999,
        [switch]$UseNetwork,
        [int]$Count = 100,
        [int]$DelayMs = 100
    )
    
    Write-Host "Emitting $Count test metrics..." -ForegroundColor Cyan
    
    if ($UseNetwork) {
        $client = [System.Net.Sockets.TcpClient]::new("localhost", $Port)
        $stream = $client.GetStream()
        $writer = [System.IO.StreamWriter]::new($stream)
    }
    else {
        $pipe = [System.IO.Pipes.NamedPipeClientStream]::new(".", $PipeName, [System.IO.Pipes.PipeDirection]::Out)
        $pipe.Connect(5000)
        $writer = [System.IO.StreamWriter]::new($pipe)
    }
    
    $metrics = @("TPS", "TTFT", "Latency", "MemoryUsage", "GPUUtilization", "SIS_Score")
    
    for ($i = 0; $i -lt $Count; $i++) {
        $metricName = $metrics | Get-Random
        $value = switch ($metricName) {
            "TPS" { Get-Random -Minimum 20 -Maximum 60 }
            "TTFT" { Get-Random -Minimum 10 -Maximum 80 }
            "Latency" { Get-Random -Minimum 20 -Maximum 150 }
            "MemoryUsage" { Get-Random -Minimum 4000 -Maximum 10000 }
            "GPUUtilization" { Get-Random -Minimum 50 -Maximum 100 }
            "SIS_Score" { Get-Random -Minimum 80 -Maximum 98 }
        }
        
        $data = @{
            Name = $metricName
            Value = $value
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Source = "test-emitter"
        } | ConvertTo-Json -Compress
        
        $writer.WriteLine($data)
        $writer.Flush()
        
        Start-Sleep -Milliseconds $DelayMs
    }
    
    $writer.Close()
    if ($client) { $client.Close() }
    if ($pipe) { $pipe.Close() }
    
    Write-Host "✓ Test metrics emitted" -ForegroundColor Green
}

#==============================================================================
# Main Execution
#==============================================================================

Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║           RawrXD Sovereign - Telemetry Collection Pipeline                   ║
║           Phase G.1 Batch 1/5: Real-time Metrics Ingestion                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

if ($Daemon) {
    $collector = [TelemetryCollector]::new($PipeName, $Port, $OutputPath, $BufferSize, $UseNetwork)
    $collector.Initialize()
    
    # Handle Ctrl+C gracefully
    [Console]::CancelKeyPress.AddListener({
        param($sender, $e)
        $e.Cancel = $true
        $collector.Stop()
        exit 0
    })
    
    $collector.StartCollection()
}
else {
    # Interactive mode
    $collector = [TelemetryCollector]::new($PipeName, $Port, $OutputPath, $BufferSize, $UseNetwork)
    $collector.Initialize()
    
    Write-Host "`nPress Enter to start collection (Ctrl+C to stop)..." -ForegroundColor Yellow
    Read-Host
    
    # Start collection in background
    $job = Start-Job -ScriptBlock {
        param($pipe, $port, $output, $buf, $net)
        $c = [TelemetryCollector]::new($pipe, $port, $output, $buf, $net)
        $c.Initialize()
        $c.StartCollection()
    } -ArgumentList $PipeName, $Port, $OutputPath, $BufferSize, $UseNetwork
    
    Write-Host "Collection started in background job" -ForegroundColor Green
    Write-Host "Run 'Emit-TestMetrics' to send test data" -ForegroundColor Yellow
    Write-Host "Press Enter to stop..." -ForegroundColor Yellow
    Read-Host
    
    Stop-Job $job
    Remove-Job $job
    
    Write-Host "✓ Collection stopped" -ForegroundColor Green
}
