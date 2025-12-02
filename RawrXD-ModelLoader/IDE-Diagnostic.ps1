# IDE Diagnostic Monitor
# Monitors the RawrXD IDE for issues and provides real-time feedback

param(
    [switch]$KillExisting,
    [switch]$WatchLog,
    [switch]$CheckResources,
    [int]$MonitorSeconds = 30
)

$ideName = "RawrXD-Win32IDE"
$logPath = "C:\RawrXD_IDE.log"
$exePath = "C:\Users\HiH8e\OneDrive\Desktop\Powershield\RawrXD-ModelLoader\build\bin\RawrXD-Win32IDE.exe"

Write-Host "=== RawrXD IDE Diagnostic Monitor ===" -ForegroundColor Cyan
Write-Host "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray

# Kill existing instances if requested
if ($KillExisting) {
    Write-Host "[1/6] Killing existing IDE processes..." -ForegroundColor Yellow
    Get-Process | Where-Object {$_.ProcessName -like "*RawrXD*"} | Stop-Process -Force
    Start-Sleep -Seconds 1
    Write-Host "  ✓ Processes terminated`n" -ForegroundColor Green
}

# Check if IDE executable exists
Write-Host "[2/6] Checking IDE executable..." -ForegroundColor Yellow
if (Test-Path $exePath) {
    $exeInfo = Get-Item $exePath
    Write-Host "  ✓ Found: $($exeInfo.FullName)" -ForegroundColor Green
    Write-Host "    Size: $([math]::Round($exeInfo.Length/1MB, 2)) MB" -ForegroundColor Gray
    Write-Host "    Modified: $($exeInfo.LastWriteTime)`n" -ForegroundColor Gray
} else {
    Write-Host "  ✗ EXECUTABLE NOT FOUND!" -ForegroundColor Red
    Write-Host "    Expected: $exePath`n" -ForegroundColor Gray
    exit 1
}

# Check log file
Write-Host "[3/6] Checking log file..." -ForegroundColor Yellow
if (Test-Path $logPath) {
    $logInfo = Get-Item $logPath
    Write-Host "  ✓ Log exists: $logPath" -ForegroundColor Green
    Write-Host "    Size: $($logInfo.Length) bytes" -ForegroundColor Gray
    Write-Host "    Last modified: $($logInfo.LastWriteTime)" -ForegroundColor Gray
    
    # Show last 10 lines
    Write-Host "`n  Last 10 log entries:" -ForegroundColor Cyan
    Get-Content $logPath -Tail 10 | ForEach-Object {
        if ($_ -match "ERROR|CRITICAL") {
            Write-Host "    $_" -ForegroundColor Red
        } elseif ($_ -match "WARNING") {
            Write-Host "    $_" -ForegroundColor Yellow
        } else {
            Write-Host "    $_" -ForegroundColor Gray
        }
    }
    Write-Host ""
} else {
    Write-Host "  ! Log file not found (will be created on IDE start)`n" -ForegroundColor Yellow
}

# Check for running IDE instances
Write-Host "[4/6] Checking for running IDE processes..." -ForegroundColor Yellow
$processes = Get-Process | Where-Object {$_.ProcessName -like "*RawrXD*"}
if ($processes) {
    Write-Host "  ✓ IDE is RUNNING" -ForegroundColor Green
    foreach ($proc in $processes) {
        Write-Host "    PID: $($proc.Id)" -ForegroundColor Gray
        Write-Host "    CPU: $($proc.CPU)s" -ForegroundColor Gray
        Write-Host "    Memory: $([math]::Round($proc.WS/1MB, 2)) MB" -ForegroundColor Gray
        Write-Host "    Handles: $($proc.Handles)" -ForegroundColor Gray
        Write-Host "    Threads: $($proc.Threads.Count)`n" -ForegroundColor Gray
    }
} else {
    Write-Host "  ! IDE is NOT running`n" -ForegroundColor Yellow
}

# Check dependencies
Write-Host "[5/6] Checking runtime dependencies..." -ForegroundColor Yellow
$d3d11 = Get-Item "$env:SystemRoot\System32\d3d11.dll" -ErrorAction SilentlyContinue
$dcomp = Get-Item "$env:SystemRoot\System32\dcomp.dll" -ErrorAction SilentlyContinue
if ($d3d11 -and $dcomp) {
    Write-Host "  ✓ DirectX 11 runtime present" -ForegroundColor Green
    Write-Host "  ✓ Desktop Window Manager runtime present`n" -ForegroundColor Green
} else {
    Write-Host "  ✗ Missing DirectX dependencies!" -ForegroundColor Red
    Write-Host "    This may cause rendering issues`n" -ForegroundColor Yellow
}

# Resource monitoring
if ($CheckResources -and $processes) {
    Write-Host "[6/6] Monitoring resources for $MonitorSeconds seconds..." -ForegroundColor Yellow
    $samples = @()
    for ($i = 0; $i -lt $MonitorSeconds; $i++) {
        $proc = Get-Process -Id $processes[0].Id -ErrorAction SilentlyContinue
        if ($proc) {
            $samples += [PSCustomObject]@{
                Time = (Get-Date)
                CPU = $proc.CPU
                MemoryMB = [math]::Round($proc.WS/1MB, 2)
                Handles = $proc.Handles
                Threads = $proc.Threads.Count
            }
        }
        Start-Sleep -Seconds 1
        Write-Host "." -NoNewline -ForegroundColor Gray
    }
    Write-Host "`n"
    
    # Analyze samples
    $avgMemory = ($samples | Measure-Object -Property MemoryMB -Average).Average
    $maxMemory = ($samples | Measure-Object -Property MemoryMB -Maximum).Maximum
    $avgHandles = ($samples | Measure-Object -Property Handles -Average).Average
    
    Write-Host "  Resource Usage Summary:" -ForegroundColor Cyan
    Write-Host "    Average Memory: $([math]::Round($avgMemory, 2)) MB" -ForegroundColor Gray
    Write-Host "    Peak Memory: $([math]::Round($maxMemory, 2)) MB" -ForegroundColor Gray
    Write-Host "    Average Handles: $([math]::Round($avgHandles, 0))" -ForegroundColor Gray
    
    if ($maxMemory -gt 500) {
        Write-Host "    ⚠️  High memory usage detected!" -ForegroundColor Yellow
    }
    if ($avgHandles -gt 5000) {
        Write-Host "    ⚠️  Potential handle leak detected!" -ForegroundColor Yellow
    }
    Write-Host ""
} else {
    Write-Host "[6/6] Resource monitoring skipped (use -CheckResources flag)`n" -ForegroundColor Gray
}

# Watch log in real-time
if ($WatchLog) {
    Write-Host "=== Watching log file (Ctrl+C to stop) ===" -ForegroundColor Cyan
    Write-Host "File: $logPath`n" -ForegroundColor Gray
    Get-Content $logPath -Wait -Tail 20 | ForEach-Object {
        $timestamp = Get-Date -Format "HH:mm:ss"
        if ($_ -match "ERROR|CRITICAL") {
            Write-Host "[$timestamp] $_" -ForegroundColor Red
        } elseif ($_ -match "WARNING") {
            Write-Host "[$timestamp] $_" -ForegroundColor Yellow
        } elseif ($_ -match "INFO") {
            Write-Host "[$timestamp] $_" -ForegroundColor Cyan
        } elseif ($_ -match "DEBUG") {
            Write-Host "[$timestamp] $_" -ForegroundColor DarkGray
        } else {
            Write-Host "[$timestamp] $_" -ForegroundColor Gray
        }
    }
}

Write-Host "=== Diagnostic Complete ===" -ForegroundColor Green
Write-Host "`nQuick Commands:" -ForegroundColor Cyan
Write-Host "  Launch IDE:          & '$exePath'" -ForegroundColor Gray
Write-Host "  Watch log:           .\IDE-Diagnostic.ps1 -WatchLog" -ForegroundColor Gray
Write-Host "  Monitor resources:   .\IDE-Diagnostic.ps1 -CheckResources -MonitorSeconds 60" -ForegroundColor Gray
Write-Host "  Kill & restart:      .\IDE-Diagnostic.ps1 -KillExisting; & '$exePath'`n" -ForegroundColor Gray
