# Build script for RawrXD VS Code Extension
param(
    [switch]$Install,
    [switch]$Package,
    [switch]$Test
)

$ErrorActionPreference = "Stop"
$extensionPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $extensionPath

Write-Host "RawrXD VS Code Extension Builder" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

# Check prerequisites
Write-Host "Checking prerequisites..." -NoNewline
$nodeVersion = node --version 2>$null
if (-not $nodeVersion) {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Error "Node.js not found. Please install Node.js 18+"
}

$npmVersion = npm --version 2>$null
if (-not $npmVersion) {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Error "npm not found"
}

Write-Host " OK (Node $nodeVersion, npm $npmVersion)" -ForegroundColor Green

# Install dependencies
Write-Host "Installing dependencies..." -NoNewline
if (-not (Test-Path "node_modules")) {
    npm install 2>&1 | Out-Null
}
Write-Host " OK" -ForegroundColor Green

# Compile TypeScript
Write-Host "Compiling TypeScript..." -NoNewline
npm run compile 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Error "TypeScript compilation failed"
}
Write-Host " OK" -ForegroundColor Green

# Copy native MASM executable
Write-Host "Copying native LSP client..." -NoNewline
$masmSource = "..\src\masm\LSPClient.exe"
$masmTarget = "out\LSPClient.exe"
if (Test-Path $masmSource) {
    Copy-Item $masmSource $masmTarget -Force
    Write-Host " OK" -ForegroundColor Green
} else {
    Write-Host " WARNING (not found)" -ForegroundColor Yellow
    Write-Host "  Run: cd ..\src\masm && build_lsp_client.bat"
}

# Install extension locally
if ($Install) {
    Write-Host "Installing extension..." -NoNewline
    $vsixPath = Join-Path $extensionPath "rawrxd-lsp-client.vsix"
    
    if (-not (Test-Path $vsixPath)) {
        npm run vscode:prepublish 2>&1 | Out-Null
        npx vsce package --out $vsixPath 2>&1 | Out-Null
    }
    
    code --install-extension $vsixPath --force 2>&1 | Out-Null
    Write-Host " OK" -ForegroundColor Green
    Write-Host "Extension installed. Reload VS Code to activate." -ForegroundColor Green
}

# Create package
if ($Package) {
    Write-Host "Creating VSIX package..." -NoNewline
    npm run vscode:prepublish 2>&1 | Out-Null
    npx vsce package 2>&1 | Out-Null
    Write-Host " OK" -ForegroundColor Green
    
    $vsix = Get-ChildItem *.vsix | Select-Object -First 1
    Write-Host "Package created: $($vsix.Name)" -ForegroundColor Green
}

# Run tests
if ($Test) {
    Write-Host "Running tests..."
    npm test 2>&1
}

Write-Host ""
Write-Host "Build complete!" -ForegroundColor Green
