# RawrXD Agentic IDE - Launch Script
# Usage: .\Launch-RawrXD.ps1 [-Model <path>] [-Agent] [-Benchmark]

param(
    [string]$Model = "",
    [switch]$Agent,
    [switch]$Benchmark,
    [switch]$Help
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$binDir = Join-Path $scriptDir "bin"
$modelsDir = Join-Path $scriptDir "models"

function Show-Help {
    Write-Host @"
╔════════════════════════════════════════════════════════╗
║           RawrXD Agentic IDE Launcher                  ║
╚════════════════════════════════════════════════════════╝

USAGE:
    .\Launch-RawrXD.ps1 [OPTIONS]

OPTIONS:
    -Model <path>    Specify model file to load
    -Agent           Launch CLI agent mode
    -Benchmark       Run GPU benchmark
    -Help            Show this help

EXAMPLES:
    .\Launch-RawrXD.ps1                    # Launch IDE
    .\Launch-RawrXD.ps1 -Agent             # Launch Agent CLI
    .\Launch-RawrXD.ps1 -Benchmark         # Run benchmarks
    .\Launch-RawrXD.ps1 -Model phi-3.gguf  # Load specific model

"@
}

function Show-Banner {
    Write-Host @"

    ██████╗  █████╗ ██╗    ██╗██████╗ ██╗  ██╗██████╗ 
    ██╔══██╗██╔══██╗██║    ██║██╔══██╗╚██╗██╔╝██╔══██╗
    ██████╔╝███████║██║ █╗ ██║██████╔╝ ╚███╔╝ ██║  ██║
    ██╔══██╗██╔══██║██║███╗██║██╔══██╗ ██╔██╗ ██║  ██║
    ██║  ██║██║  ██║╚███╔███╔╝██║  ██║██╔╝ ██╗██████╔╝
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
    
    Agentic IDE - 2x Faster Than Cloud Solutions
    
"@ -ForegroundColor Cyan
}

function Find-Models {
    if (Test-Path $modelsDir) {
        $models = Get-ChildItem -Path $modelsDir -Filter "*.gguf" -ErrorAction SilentlyContinue
        if ($models.Count -gt 0) {
            Write-Host "📦 Available Models:" -ForegroundColor Green
            foreach ($m in $models) {
                $sizeMB = [math]::Round($m.Length / 1MB, 1)
                Write-Host "   • $($m.Name) ($sizeMB MB)" -ForegroundColor White
            }
            Write-Host ""
        }
    }
}

function Test-Prerequisites {
    $exe = Join-Path $binDir "RawrXD-Win32IDE.exe"
    if (-not (Test-Path $exe)) {
        Write-Host "❌ ERROR: RawrXD-Win32IDE.exe not found in bin/" -ForegroundColor Red
        Write-Host "   Please ensure binaries are properly installed." -ForegroundColor Yellow
        exit 1
    }
    
    # Check for Qt DLLs
    $qtCore = Join-Path $binDir "Qt6Core.dll"
    if (-not (Test-Path $qtCore)) {
        Write-Host "⚠️  WARNING: Qt6Core.dll not found. IDE may not launch." -ForegroundColor Yellow
    }
}

# Main execution
if ($Help) {
    Show-Help
    exit 0
}

Show-Banner
Test-Prerequisites
Find-Models

if ($Benchmark) {
    Write-Host "🔥 Running GPU Benchmark..." -ForegroundColor Yellow
    $benchExe = Join-Path $binDir "gpu_inference_benchmark.exe"
    
    if ($Model -ne "" -and (Test-Path $Model)) {
        & $benchExe $Model
    } elseif (Test-Path $modelsDir) {
        $firstModel = Get-ChildItem -Path $modelsDir -Filter "*.gguf" | Select-Object -First 1
        if ($firstModel) {
            & $benchExe $firstModel.FullName
        } else {
            Write-Host "❌ No models found. Place GGUF files in models/ folder." -ForegroundColor Red
        }
    }
    exit 0
}

if ($Agent) {
    Write-Host "🤖 Launching RawrXD Agent..." -ForegroundColor Cyan
    $agentExe = Join-Path $binDir "RawrXD-Agent.exe"
    Write-Host "   Enter your wish (or 'exit' to quit):" -ForegroundColor White
    & $agentExe
    exit 0
}

# Default: Launch IDE
Write-Host "🚀 Launching RawrXD IDE..." -ForegroundColor Green
$ideExe = Join-Path $binDir "RawrXD-Win32IDE.exe"

if ($Model -ne "") {
    Write-Host "   Loading model: $Model" -ForegroundColor White
    Start-Process -FilePath $ideExe -ArgumentList "--model", $Model
} else {
    Start-Process -FilePath $ideExe
}

Write-Host "✅ IDE launched successfully!" -ForegroundColor Green
