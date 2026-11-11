# RawrXD Diagnostic Tools
# System diagnostics and troubleshooting utilities

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("System", "Network", "Storage", "Memory", "GPU", "All", "Quick", "Deep")]
    [string]$DiagnosticType = "Quick",
    
    [string]$OutputPath = "",
    [switch]$FixIssues,
    [switch]$Verbose,
    [switch]$JsonOutput
)

$ErrorActionPreference = "Stop"

# Diagnostic results storage
$script:DiagnosticResults = @()
$script:IssuesFound = 0
$script:IssuesFixed = 0

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Add-DiagnosticResult {
    param(
        [string]$Category,
        [string]$Test,
        [string]$Status,  # Pass, Fail, Warning
        [string]$Message,
        [string]$Recommendation = ""
    )
    
    $result = [PSCustomObject]@{
        Category = $Category
        Test = $Test
        Status = $Status
        Message = $Message
        Recommendation = $Recommendation
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $script:DiagnosticResults += $result
    
    if ($Status -eq "Fail") { $script:IssuesFound++ }
}

function Test-SystemHealth {
    Write-Status "Running system health diagnostics..."
    
    # Check CPU
    $cpu = Get-Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 3 | 
           Select-Object -ExpandProperty CounterSamples | 
           Measure-Object -Property CookedValue -Average
    
    $cpuAvg = [math]::Round($cpu.Average, 2)
    if ($cpuAvg -gt 90) {
        Add-DiagnosticResult -Category "System" -Test "CPU Usage" -Status "Fail" `
            -Message "CPU usage is critically high: $cpuAvg%" `
            -Recommendation "Close unnecessary applications or upgrade hardware"
    } elseif ($cpuAvg -gt 70) {
        Add-DiagnosticResult -Category "System" -Test "CPU Usage" -Status "Warning" `
            -Message "CPU usage is elevated: $cpuAvg%" `
            -Recommendation "Monitor for sustained high usage"
    } else {
        Add-DiagnosticResult -Category "System" -Test "CPU Usage" -Status "Pass" `
            -Message "CPU usage is normal: $cpuAvg%"
    }
    
    # Check memory
    $os = Get-CimInstance Win32_OperatingSystem
    $totalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $freeGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    $usedPercent = [math]::Round((($totalGB - $freeGB) / $totalGB) * 100, 2)
    
    if ($usedPercent -gt 95) {
        Add-DiagnosticResult -Category "System" -Test "Memory Usage" -Status "Fail" `
            -Message "Memory critically low: $usedPercent% used ($freeGB GB free of $totalGB GB)" `
            -Recommendation "Close applications or add more RAM"
    } elseif ($usedPercent -gt 85) {
        Add-DiagnosticResult -Category "System" -Test "Memory Usage" -Status "Warning" `
            -Message "Memory usage is high: $usedPercent% used" `
            -Recommendation "Consider closing unused applications"
    } else {
        Add-DiagnosticResult -Category "System" -Test "Memory Usage" -Status "Pass" `
            -Message "Memory usage is healthy: $usedPercent% used ($freeGB GB free)"
    }
    
    # Check disk space
    $disks = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
    foreach ($disk in $disks) {
        $freePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
        $drive = $disk.DeviceID
        
        if ($freePercent -lt 5) {
            Add-DiagnosticResult -Category "System" -Test "Disk Space ($drive)" -Status "Fail" `
                -Message "Disk $drive critically low on space: $freePercent% free" `
                -Recommendation "Free up disk space immediately"
        } elseif ($freePercent -lt 15) {
            Add-DiagnosticResult -Category "System" -Test "Disk Space ($drive)" -Status "Warning" `
                -Message "Disk $drive running low on space: $freePercent% free" `
                -Recommendation "Clean up temporary files"
        } else {
            Add-DiagnosticResult -Category "System" -Test "Disk Space ($drive)" -Status "Pass" `
                -Message "Disk $drive has adequate space: $freePercent% free"
        }
    }
    
    # Check RawrXD service
    $service = Get-Service -Name "RawrXD*" -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq "Running") {
            Add-DiagnosticResult -Category "System" -Test "RawrXD Service" -Status "Pass" `
                -Message "RawrXD service is running"
        } else {
            Add-DiagnosticResult -Category "System" -Test "RawrXD Service" -Status "Fail" `
                -Message "RawrXD service is not running (Status: $($service.Status))" `
                -Recommendation "Start the service: Start-Service $($service.Name)"
            
            if ($FixIssues) {
                try {
                    Start-Service $service.Name
                    $script:IssuesFixed++
                    Write-Success "Started RawrXD service"
                }
                catch {
                    Write-Error "Failed to start service: $_"
                }
            }
        }
    } else {
        Add-DiagnosticResult -Category "System" -Test "RawrXD Service" -Status "Warning" `
            -Message "RawrXD service not found" `
            -Recommendation "Verify installation"
    }
}

function Test-NetworkHealth {
    Write-Status "Running network diagnostics..."
    
    # Check network connectivity
    $pingResults = @()
    $targets = @("8.8.8.8", "1.1.1.1", "rawrxd.local")
    
    foreach ($target in $targets) {
        try {
            $ping = Test-Connection -ComputerName $target -Count 2 -ErrorAction Stop
            $avgLatency = ($ping | Measure-Object -Property ResponseTime -Average).Average
            $pingResults += @{ Target = $target; Latency = $avgLatency; Success = $true }
        }
        catch {
            $pingResults += @{ Target = $target; Latency = 0; Success = $false }
        }
    }
    
    $successCount = ($pingResults | Where-Object { $_.Success }).Count
    if ($successCount -eq 0) {
        Add-DiagnosticResult -Category "Network" -Test "Connectivity" -Status "Fail" `
            -Message "No network connectivity detected" `
            -Recommendation "Check network adapter and cables"
    } elseif ($successCount -lt $targets.Count) {
        Add-DiagnosticResult -Category "Network" -Test "Connectivity" -Status "Warning" `
            -Message "Partial connectivity: $successCount/$($targets.Count) targets reachable" `
            -Recommendation "Check firewall and DNS settings"
    } else {
        $avgLatency = ($pingResults | Measure-Object -Property Latency -Average).Average
        Add-DiagnosticResult -Category "Network" -Test "Connectivity" -Status "Pass" `
            -Message "Network connectivity OK (avg latency: $([math]::Round($avgLatency, 2)) ms)"
    }
    
    # Check network adapters
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    if ($adapters.Count -eq 0) {
        Add-DiagnosticResult -Category "Network" -Test "Network Adapters" -Status "Fail" `
            -Message "No active network adapters found" `
            -Recommendation "Enable network adapter"
    } else {
        Add-DiagnosticResult -Category "Network" -Test "Network Adapters" -Status "Pass" `
            -Message "$($adapters.Count) active adapter(s) found"
    }
    
    # Check DNS resolution
    try {
        Resolve-DnsName -Name "rawrxd.io" -ErrorAction Stop | Out-Null
        Add-DiagnosticResult -Category "Network" -Test "DNS Resolution" -Status "Pass" `
            -Message "DNS resolution working"
    }
    catch {
        Add-DiagnosticResult -Category "Network" -Test "DNS Resolution" -Status "Warning" `
            -Message "DNS resolution issues detected" `
            -Recommendation "Check DNS server configuration"
    }
}

function Test-StorageHealth {
    Write-Status "Running storage diagnostics..."
    
    # Check disk health
    $physicalDisks = Get-PhysicalDisk -ErrorAction SilentlyContinue
    if ($physicalDisks) {
        foreach ($disk in $physicalDisks) {
            $health = $disk.HealthStatus
            if ($health -eq "Healthy") {
                Add-DiagnosticResult -Category "Storage" -Test "Physical Disk $($disk.DeviceId)" -Status "Pass" `
                    -Message "Disk is healthy"
            } else {
                Add-DiagnosticResult -Category "Storage" -Test "Physical Disk $($disk.DeviceId)" -Status "Fail" `
                    -Message "Disk health status: $health" `
                    -Recommendation "Backup data and replace disk immediately"
            }
        }
    }
    
    # Check for disk errors
    $diskErrors = Get-EventLog -LogName System -Source "disk" -EntryType Error -Newest 10 -ErrorAction SilentlyContinue
    if ($diskErrors) {
        Add-DiagnosticResult -Category "Storage" -Test "Disk Errors" -Status "Warning" `
            -Message "$($diskErrors.Count) disk errors found in event log" `
            -Recommendation "Run chkdsk to check disk integrity"
    } else {
        Add-DiagnosticResult -Category "Storage" -Test "Disk Errors" -Status "Pass" `
            -Message "No recent disk errors"
    }
    
    # Check temp directory
    $tempPath = $env:TEMP
    $tempSize = (Get-ChildItem $tempPath -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    $tempSizeGB = [math]::Round($tempSize / 1GB, 2)
    
    if ($tempSizeGB -gt 10) {
        Add-DiagnosticResult -Category "Storage" -Test "Temp Directory" -Status "Warning" `
            -Message "Temp directory is large: $tempSizeGB GB" `
            -Recommendation "Clean up temporary files"
        
        if ($FixIssues) {
            try {
                Remove-Item "$tempPath\*" -Recurse -Force -ErrorAction SilentlyContinue
                $script:IssuesFixed++
                Write-Success "Cleaned temporary files"
            }
            catch {
                Write-Error "Failed to clean temp: $_"
            }
        }
    } else {
        Add-DiagnosticResult -Category "Storage" -Test "Temp Directory" -Status "Pass" `
            -Message "Temp directory size OK: $tempSizeGB GB"
    }
}

function Test-MemoryHealth {
    Write-Status "Running memory diagnostics..."
    
    # Check for memory errors in event log
    $memoryErrors = Get-EventLog -LogName System -Source "*memory*" -EntryType Error -Newest 5 -ErrorAction SilentlyContinue
    if ($memoryErrors) {
        Add-DiagnosticResult -Category "Memory" -Test "Memory Errors" -Status "Fail" `
            -Message "$($memoryErrors.Count) memory errors found" `
            -Recommendation "Run Windows Memory Diagnostic"
    } else {
        Add-DiagnosticResult -Category "Memory" -Test "Memory Errors" -Status "Pass" `
            -Message "No memory errors detected"
    }
    
    # Check page file
    $pageFile = Get-CimInstance Win32_PageFileUsage
    if ($pageFile) {
        $usagePercent = [math]::Round(($pageFile.CurrentUsage / $pageFile.AllocatedBaseSize) * 100, 2)
        if ($usagePercent -gt 90) {
            Add-DiagnosticResult -Category "Memory" -Test "Page File" -Status "Warning" `
                -Message "Page file usage is high: $usagePercent%" `
                -Recommendation "Increase page file size or add more RAM"
        } else {
            Add-DiagnosticResult -Category "Memory" -Test "Page File" -Status "Pass" `
                -Message "Page file usage normal: $usagePercent%"
        }
    }
    
    # Check for memory leaks (simplified)
    $processes = Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 5
    $highMemory = $processes | Where-Object { $_.WorkingSet / 1GB -gt 1 }
    
    if ($highMemory) {
        $procNames = ($highMemory | ForEach-Object { "$($_.Name) ($([math]::Round($_.WorkingSet/1GB,2)) GB)" }) -join ", "
        Add-DiagnosticResult -Category "Memory" -Test "High Memory Processes" -Status "Warning" `
            -Message "High memory usage: $procNames" `
            -Recommendation "Investigate processes for memory leaks"
    }
}

function Test-GPUHealth {
    Write-Status "Running GPU diagnostics..."
    
    # Check for GPU
    $gpus = Get-CimInstance Win32_VideoController
    if ($gpus) {
        foreach ($gpu in $gpus) {
            Add-DiagnosticResult -Category "GPU" -Test "GPU Detection ($($gpu.Name))" -Status "Pass" `
                -Message "GPU detected: $($gpu.Name) ($([math]::Round($gpu.AdapterRAM/1GB,2)) GB)"
        }
        
        # Check GPU driver
        $driverVersion = $gpus[0].DriverVersion
        if ($driverVersion) {
            Add-DiagnosticResult -Category "GPU" -Test "Driver Version" -Status "Pass" `
                -Message "Driver version: $driverVersion"
        }
    } else {
        Add-DiagnosticResult -Category "GPU" -Test "GPU Detection" -Status "Warning" `
            -Message "No GPU detected" `
            -Recommendation "Verify GPU installation"
    }
    
    # Check for GPU errors
    $gpuErrors = Get-EventLog -LogName System -Source "*nvidia*" -EntryType Error -Newest 5 -ErrorAction SilentlyContinue
    if ($gpuErrors) {
        Add-DiagnosticResult -Category "GPU" -Test "GPU Errors" -Status "Warning" `
            -Message "$($gpuErrors.Count) GPU errors found" `
            -Recommendation "Update GPU drivers"
    }
}

function Show-Results {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Diagnostic Results Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    $categories = $script:DiagnosticResults | Group-Object -Property Category
    
    foreach ($cat in $categories) {
        Write-Host "$($cat.Name) Diagnostics:" -ForegroundColor White
        Write-Host "----------------------------------------" -ForegroundColor Gray
        
        foreach ($result in $cat.Group) {
            $color = switch ($result.Status) {
                "Pass" { "Green" }
                "Fail" { "Red" }
                "Warning" { "Yellow" }
            }
            
            Write-Host "  [$($result.Status)] $($result.Test)" -ForegroundColor $color
            Write-Host "      $($result.Message)" -ForegroundColor Gray
            
            if ($result.Recommendation) {
                Write-Host "      → $($result.Recommendation)" -ForegroundColor Cyan
            }
            Write-Host ""
        }
    }
    
    $passCount = ($script:DiagnosticResults | Where-Object { $_.Status -eq "Pass" }).Count
    $failCount = ($script:DiagnosticResults | Where-Object { $_.Status -eq "Fail" }).Count
    $warnCount = ($script:DiagnosticResults | Where-Object { $_.Status -eq "Warning" }).Count
    
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Summary: $passCount passed, $failCount failed, $warnCount warnings" -ForegroundColor White
    
    if ($script:IssuesFixed -gt 0) {
        Write-Host "Issues automatically fixed: $script:IssuesFixed" -ForegroundColor Green
    }
    
    if ($failCount -gt 0) {
        Write-Host "`nAction required: Please address failed diagnostics" -ForegroundColor Red
    } elseif ($warnCount -gt 0) {
        Write-Host "`nRecommendation: Review warnings for optimization" -ForegroundColor Yellow
    } else {
        Write-Host "`nAll diagnostics passed!" -ForegroundColor Green
    }
}

function Export-Results {
    if (-not $OutputPath) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $OutputPath = "diagnostic_report_$timestamp.json"
    }
    
    $report = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        System = $env:COMPUTERNAME
        User = $env:USERNAME
        Summary = @{
            Total = $script:DiagnosticResults.Count
            Passed = ($script:DiagnosticResults | Where-Object { $_.Status -eq "Pass" }).Count
            Failed = ($script:DiagnosticResults | Where-Object { $_.Status -eq "Fail" }).Count
            Warnings = ($script:DiagnosticResults | Where-Object { $_.Status -eq "Warning" }).Count
            IssuesFixed = $script:IssuesFixed
        }
        Results = $script:DiagnosticResults
    }
    
    if ($JsonOutput) {
        $report | ConvertTo-Json -Depth 10 | Out-File $OutputPath
    } else {
        $report | Export-Clixml $OutputPath
    }
    
    Write-Success "Report exported to: $OutputPath"
}

# Main execution
function Main {
    Write-Host "RawrXD Diagnostic Tools" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan
    Write-Host ""
    
    switch ($DiagnosticType) {
        "Quick" {
            Test-SystemHealth
            Test-NetworkHealth
        }
        "Deep" {
            Test-SystemHealth
            Test-NetworkHealth
            Test-StorageHealth
            Test-MemoryHealth
            Test-GPUHealth
        }
        "System" { Test-SystemHealth }
        "Network" { Test-NetworkHealth }
        "Storage" { Test-StorageHealth }
        "Memory" { Test-MemoryHealth }
        "GPU" { Test-GPUHealth }
        "All" {
            Test-SystemHealth
            Test-NetworkHealth
            Test-StorageHealth
            Test-MemoryHealth
            Test-GPUHealth
        }
    }
    
    Show-Results
    
    if ($OutputPath -or $JsonOutput) {
        Export-Results
    }
}

Main
