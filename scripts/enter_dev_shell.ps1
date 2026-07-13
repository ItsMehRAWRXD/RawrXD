<#
.SYNOPSIS
    RawrXD Development Shell Entry Script
    
.DESCRIPTION
    Configures the environment for RawrXD development including paths,
    toolchains, and environment variables. Source this in your PowerShell
    session to enter the development environment.
    
.EXAMPLE
    .\enter_dev_shell.ps1
    
.EXAMPLE
    . .\enter_dev_shell.ps1  # Source into current session
#>

[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [switch]$SkipVSInit,
    [switch]$VerboseEnv
)

$ErrorActionPreference = "Stop"

# Script directory and project root
$script:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:ProjectRoot = Split-Path -Parent $script:ScriptDir

Write-Host "RawrXD Development Environment" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host ""

# Detect Visual Studio
function Initialize-VisualStudio {
    if ($SkipVSInit) {
        Write-Host "[VS] Skipping Visual Studio initialization" -ForegroundColor Yellow
        return
    }
    
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    
    if (Test-Path $vsWhere) {
        $vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($vsPath) {
            $vcvarsPath = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
            if (Test-Path $vcvarsPath) {
                Write-Host "[VS] Found Visual Studio at: $vsPath" -ForegroundColor Green
                
                # Extract environment from vcvars64.bat
                $tempFile = [System.IO.Path]::GetTempFileName()
                cmd /c "`"$vcvarsPath`" && set > `"$tempFile`"" 2>$null
                
                Get-Content $tempFile | ForEach-Object {
                    if ($_ -match '^(\w+)=(.*)$') {
                        $name = $matches[1]
                        $value = $matches[2]
                        Set-Item -Path "Env:$name" -Value $value -ErrorAction SilentlyContinue
                    }
                }
                
                Remove-Item $tempFile -ErrorAction SilentlyContinue
                Write-Host "[VS] Environment configured for x64" -ForegroundColor Green
            }
        }
    }
    else {
        # Try common paths
        $commonPaths = @(
            "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
            "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
            "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
            "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
            "D:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat"
        )
        
        foreach ($path in $commonPaths) {
            if (Test-Path $path) {
                Write-Host "[VS] Found vcvars64.bat at: $path" -ForegroundColor Green
                
                $tempFile = [System.IO.Path]::GetTempFileName()
                cmd /c "`"$path`" && set > `"$tempFile`"" 2>$null
                
                Get-Content $tempFile | ForEach-Object {
                    if ($_ -match '^(\w+)=(.*)$') {
                        $name = $matches[1]
                        $value = $matches[2]
                        Set-Item -Path "Env:$name" -Value $value -ErrorAction SilentlyContinue
                    }
                }
                
                Remove-Item $tempFile -ErrorAction SilentlyContinue
                Write-Host "[VS] Environment configured for x64" -ForegroundColor Green
                break
            }
        }
    }
}

# Configure Vulkan SDK
function Initialize-Vulkan {
    if ($env:VULKAN_SDK) {
        Write-Host "[Vulkan] SDK found at: $env:VULKAN_SDK" -ForegroundColor Green
        
        $vulkanBin = Join-Path $env:VULKAN_SDK "Bin"
        $vulkanLib = Join-Path $env:VULKAN_SDK "Lib"
        
        if ($env:Path -notlike "*$vulkanBin*") {
            $env:Path = "$vulkanBin;$env:Path"
        }
        
        Write-Host "[Vulkan] Added to PATH" -ForegroundColor Green
    }
    else {
        Write-Host "[Vulkan] SDK not found. Some features may be unavailable." -ForegroundColor Yellow
    }
}

# Configure Python environment
function Initialize-Python {
    if (Get-Command python -ErrorAction SilentlyContinue) {
        $pythonVersion = & python --version 2>&1
        Write-Host "[Python] $pythonVersion" -ForegroundColor Green
        
        # Check for required packages
        $requiredPackages = @("numpy", "requests")
        foreach ($pkg in $requiredPackages) {
            $result = & python -c "import $pkg" 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[Python] $pkg: OK" -ForegroundColor Green
            }
            else {
                Write-Host "[Python] $pkg: Not installed (pip install $pkg)" -ForegroundColor Yellow
            }
        }
    }
    else {
        Write-Host "[Python] Not found in PATH" -ForegroundColor Yellow
    }
}

# Configure CMake
function Initialize-CMake {
    if (Get-Command cmake -ErrorAction SilentlyContinue) {
        $cmakeVersion = & cmake --version | Select-Object -First 1
        Write-Host "[CMake] $cmakeVersion" -ForegroundColor Green
    }
    else {
        Write-Host "[CMake] Not found in PATH" -ForegroundColor Yellow
    }
}

# Configure Ninja
function Initialize-Ninja {
    if (Get-Command ninja -ErrorAction SilentlyContinue) {
        $ninjaVersion = & ninja --version
        Write-Host "[Ninja] Version $ninjaVersion" -ForegroundColor Green
    }
    else {
        Write-Host "[Ninja] Not found in PATH (optional, but recommended)" -ForegroundColor Yellow
    }
}

# Set RawrXD-specific environment
function Initialize-RawrXDEnvironment {
    $env:RAWRXD_ROOT = $script:ProjectRoot
    $env:RAWRXD_BUILD_DIR = Join-Path $script:ProjectRoot "build-$Configuration".ToLower()
    $env:RAWRXD_CONFIG = $Configuration
    
    Write-Host "[RawrXD] Root: $env:RAWRXD_ROOT" -ForegroundColor Cyan
    Write-Host "[RawrXD] Build: $env:RAWRXD_BUILD_DIR" -ForegroundColor Cyan
    Write-Host "[RawrXD] Config: $env:RAWRXD_CONFIG" -ForegroundColor Cyan
}

# Create build directory
function Initialize-BuildDirectory {
    if (-not (Test-Path $env:RAWRXD_BUILD_DIR)) {
        New-Item -ItemType Directory -Path $env:RAWRXD_BUILD_DIR -Force | Out-Null
        Write-Host "[Build] Created directory: $env:RAWRXD_BUILD_DIR" -ForegroundColor Green
    }
}

# Define helper functions
function global:Invoke-RawrXDBuild {
    [CmdletBinding()]
    param(
        [string]$Target = "all",
        [string]$Config = $env:RAWRXD_CONFIG,
        [switch]$Clean
    )
    
    Push-Location $env:RAWRXD_BUILD_DIR
    try {
        if ($Clean) {
            Write-Host "Cleaning build directory..." -ForegroundColor Yellow
            Remove-Item -Recurse -Force * -ErrorAction SilentlyContinue
        }
        
        if (-not (Test-Path "CMakeCache.txt")) {
            Write-Host "Configuring with CMake..." -ForegroundColor Cyan
            & cmake -G Ninja -DCMAKE_BUILD_TYPE=$Config $env:RAWRXD_ROOT
            if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed" }
        }
        
        Write-Host "Building target: $Target" -ForegroundColor Cyan
        & cmake --build . --target $Target --config $Config -j (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
        if ($LASTEXITCODE -ne 0) { throw "Build failed" }
        
        Write-Host "Build completed successfully!" -ForegroundColor Green
    }
    finally {
        Pop-Location
    }
}

function global:Invoke-RawrXDTest {
    [CmdletBinding()]
    param(
        [string]$Pattern = "",
        [switch]$Verbose
    )
    
    Push-Location $env:RAWRXD_BUILD_DIR
    try {
        $testArgs = @("--output-on-failure")
        if ($Verbose) { $testArgs += "-V" }
        if ($Pattern) { $testArgs += "-R", $Pattern }
        
        & ctest @testArgs
    }
    finally {
        Pop-Location
    }
}

function global:Enter-RawrXDBinaryDir {
    Set-Location (Join-Path $env:RAWRXD_BUILD_DIR "bin")
}

# Aliases
Set-Alias -Name rbuild -Value Invoke-RawrXDBuild -Scope Global
Set-Alias -Name rtest -Value Invoke-RawrXDTest -Scope Global
Set-Alias -Name rbin -Value Enter-RawrXDBinaryDir -Scope Global

# Initialize everything
Initialize-VisualStudio
Initialize-Vulkan
Initialize-Python
Initialize-CMake
Initialize-Ninja
Initialize-RawrXDEnvironment
Initialize-BuildDirectory

# Print summary
Write-Host ""
Write-Host "Available Commands:" -ForegroundColor Cyan
Write-Host "  rbuild [-Target <name>] [-Clean]     - Build RawrXD" -ForegroundColor White
Write-Host "  rtest [-Pattern <regex>] [-Verbose]    - Run tests" -ForegroundColor White
Write-Host "  rbin                                   - Enter binary directory" -ForegroundColor White
Write-Host ""
Write-Host "Environment Variables:" -ForegroundColor Cyan
if ($VerboseEnv) {
    Get-ChildItem Env: | Where-Object { $_.Name -match '^(VULKAN|RAWRXD|CMAKE|CC|CXX)' } | 
        ForEach-Object { Write-Host "  $($_.Name)=$($_.Value)" -ForegroundColor Gray }
}
else {
    Write-Host "  RAWRXD_ROOT=$env:RAWRXD_ROOT" -ForegroundColor Gray
    Write-Host "  RAWRXD_BUILD_DIR=$env:RAWRXD_BUILD_DIR" -ForegroundColor Gray
    Write-Host "  RAWRXD_CONFIG=$env:RAWRXD_CONFIG" -ForegroundColor Gray
    Write-Host "  VULKAN_SDK=$env:VULKAN_SDK" -ForegroundColor Gray
}
Write-Host ""
Write-Host "Development environment ready!" -ForegroundColor Green
