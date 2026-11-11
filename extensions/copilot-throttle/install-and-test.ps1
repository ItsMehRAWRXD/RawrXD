# Copilot Throttle Extension - Install and Test Script
param(
    [switch]$Build,
    [switch]$Install,
    [switch]$Test,
    [switch]$Proxy,
    [switch]$All
)

$extensionDir = "d:\rawrxd\extensions\copilot-throttle"
$ErrorActionPreference = "Stop"

function Build-Extension {
    Write-Host "🔨 Building Copilot Throttle Extension..." -ForegroundColor Cyan
    Set-Location $extensionDir
    
    # Check if node_modules exists
    if (-not (Test-Path "node_modules")) {
        Write-Host "📦 Installing dependencies..." -ForegroundColor Yellow
        npm install
    }
    
    # Compile TypeScript
    Write-Host "📋 Compiling TypeScript..." -ForegroundColor Yellow
    npx tsc -p ./
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Build successful!" -ForegroundColor Green
    } else {
        Write-Host "❌ Build failed!" -ForegroundColor Red
        exit 1
    }
}

function Install-Extension {
    Write-Host "📥 Installing extension to VS Code..." -ForegroundColor Cyan
    Set-Location $extensionDir
    
    # Package the extension
    if (-not (Test-Path "out\extension.js")) {
        Build-Extension
    }
    
    # Install using vsce or directly
    $vsixPath = "$extensionDir\copilot-throttle-1.0.0.vsix"
    
    if (Test-Path $vsixPath) {
        Remove-Item $vsixPath -Force
    }
    
    # Try to package with vsce
    try {
        npx vsce package --out $vsixPath 2>$null
        if (Test-Path $vsixPath) {
            code --install-extension $vsixPath --force
            Write-Host "✅ Extension installed from VSIX" -ForegroundColor Green
        }
    } catch {
        # Fallback: direct development install
        Write-Host "📦 Installing in development mode..." -ForegroundColor Yellow
        code --extensionDevelopmentPath=$extensionDir
        Write-Host "✅ Extension loaded in development mode" -ForegroundColor Green
    }
    
    Write-Host "`n📝 To activate: Press F1 and run 'Toggle Copilot Throttle'" -ForegroundColor Cyan
}

function Start-ProxyServer {
    Write-Host "🚀 Starting Throttle Proxy Server..." -ForegroundColor Cyan
    Set-Location $extensionDir
    
    # Check if http-proxy is installed
    if (-not (Test-Path "node_modules\http-proxy")) {
        Write-Host "📦 Installing http-proxy..." -ForegroundColor Yellow
        npm install http-proxy
    }
    
    # Start proxy in new window
    $proxyScript = "$extensionDir\proxy-server.js"
    
    Write-Host "`n🌐 Proxy Configuration:" -ForegroundColor Cyan
    Write-Host "   Port: 9091 (throttled)" -ForegroundColor White
    Write-Host "   Target: 9090 (RawrXD)" -ForegroundColor White
    Write-Host "   Max Tokens: 2048" -ForegroundColor White
    Write-Host "   Max Chars: 8000" -ForegroundColor White
    Write-Host "`n⚠️  Make sure RawrXD is running on port 9090 first!" -ForegroundColor Yellow
    
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$extensionDir'; node proxy-server.js" -WindowStyle Normal
    
    Write-Host "`n✅ Proxy server started in new window" -ForegroundColor Green
    Write-Host "📝 Configure Copilot to use http://127.0.0.1:9091 instead of :9090" -ForegroundColor Cyan
}

function Test-Throttle {
    Write-Host "🧪 Testing Throttle Configuration..." -ForegroundColor Cyan
    
    # Test 1: Check if RawrXD is running
    Write-Host "`n1️⃣ Checking RawrXD status..." -ForegroundColor Yellow
    try {
        $response = Invoke-RestMethod -Uri "http://127.0.0.1:9090/api/status" -Method GET -TimeoutSec 5
        Write-Host "   ✅ RawrXD is running on port 9090" -ForegroundColor Green
    } catch {
        Write-Host "   ❌ RawrXD not responding on port 9090" -ForegroundColor Red
        Write-Host "   Start RawrXD first: .\bin\RawrXD-Win32IDE.exe" -ForegroundColor Yellow
        return
    }
    
    # Test 2: Test proxy (if running)
    Write-Host "`n2️⃣ Checking Proxy Server..." -ForegroundColor Yellow
    try {
        $response = Invoke-RestMethod -Uri "http://127.0.0.1:9091/api/status" -Method GET -TimeoutSec 3
        Write-Host "   ✅ Proxy is running on port 9091" -ForegroundColor Green
    } catch {
        Write-Host "   ⏸️ Proxy not running on port 9091 (start with -Proxy flag)" -ForegroundColor Yellow
    }
    
    # Test 3: Test throttled request
    Write-Host "`n3️⃣ Testing Throttled Request..." -ForegroundColor Yellow
    $testBody = @{
        model = "tinyllama"
        prompt = "Hello"
        max_tokens = 4096  # Will be throttled to 2048
        stream = $false    # Will be forced to true
    } | ConvertTo-Json
    
    try {
        $response = Invoke-RestMethod -Uri "http://127.0.0.1:9091/v1/chat/completions" -Method POST -Body $testBody -ContentType "application/json" -TimeoutSec 10
        Write-Host "   ✅ Request processed through proxy" -ForegroundColor Green
    } catch {
        Write-Host "   ⚠️  Request test: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    Write-Host "`n📊 Test Complete" -ForegroundColor Cyan
}

# Main execution
Write-Host "`n╔════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     Copilot Throttle Extension - Setup & Test         ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

if ($All) {
    Build-Extension
    Install-Extension
    Start-ProxyServer
    Start-Sleep -Seconds 2
    Test-Throttle
} elseif ($Build) {
    Build-Extension
} elseif ($Install) {
    Install-Extension
} elseif ($Proxy) {
    Start-ProxyServer
} elseif ($Test) {
    Test-Throttle
} else {
    Write-Host "`nUsage:" -ForegroundColor White
    Write-Host "  .\install-and-test.ps1 -Build    # Build the extension" -ForegroundColor Gray
    Write-Host "  .\install-and-test.ps1 -Install  # Install to VS Code" -ForegroundColor Gray
    Write-Host "  .\install-and-test.ps1 -Proxy    # Start proxy server" -ForegroundColor Gray
    Write-Host "  .\install-and-test.ps1 -Test     # Test configuration" -ForegroundColor Gray
    Write-Host "  .\install-and-test.ps1 -All      # Do everything" -ForegroundColor Gray
    Write-Host "`nQuick start: .\install-and-test.ps1 -All" -ForegroundColor Cyan
}

Set-Location $PSScriptRoot
