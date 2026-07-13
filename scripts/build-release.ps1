# RawrXD Release Build Script
# Creates optimized release builds for distribution

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Release", "RelWithDebInfo", "MinSizeRel")]
    [string]$BuildType = "Release",
    
    [switch]$EnableCUDA,
    [switch]$EnableVulkan,
    [switch]$EnableAVX512,
    [switch]$StaticLink,
    [string]$OutputPath = "dist",
    [string]$Version = "3.2.0",
    [switch]$Package,
    [switch]$SignBinaries
)

$ErrorActionPreference = "Stop"

# Configuration
$script:Config = @{
    BuildDir = "build-release"
    DistDir = $OutputPath
    Version = $Version
    BuildType = $BuildType
}

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

function Initialize-BuildEnvironment {
    Write-Status "Initializing build environment..."
    
    # Clean previous build
    if (Test-Path $script:Config.BuildDir) {
        Remove-Item -Recurse -Force $script:Config.BuildDir
    }
    
    New-Item -ItemType Directory -Path $script:Config.BuildDir -Force | Out-Null
    
    if ($Package) {
        if (Test-Path $script:Config.DistDir) {
            Remove-Item -Recurse -Force $script:Config.DistDir
        }
        New-Item -ItemType Directory -Path $script:Config.DistDir -Force | Out-Null
    }
    
    Write-Success "Build environment initialized"
}

function Get-CMakeArguments {
    $args = @(
        "..",
        "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=$($script:Config.BuildType)",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        "-DRAWRXD_BUILD_TESTS=ON",
        "-DRAWRXD_BUILD_EXAMPLES=ON"
    )
    
    if ($EnableCUDA) {
        $args += "-DGGML_CUDA=ON"
        $args += "-DGGML_CUDA_F16=ON"
        Write-Status "CUDA support enabled"
    }
    
    if ($EnableVulkan) {
        $args += "-DGGML_VULKAN=ON"
        Write-Status "Vulkan support enabled"
    }
    
    if ($EnableAVX512) {
        $args += "-DGGML_AVX512=ON"
        Write-Status "AVX-512 support enabled"
    }
    
    if ($StaticLink) {
        $args += "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded"
        $args += "-DBUILD_SHARED_LIBS=OFF"
        Write-Status "Static linking enabled"
    }
    
    return $args
}

function Invoke-Configure {
    Write-Status "Configuring with CMake..."
    
    Set-Location $script:Config.BuildDir
    
    $cmakeArgs = Get-CMakeArguments
    
    & cmake @cmakeArgs
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "CMake configuration failed"
        exit 1
    }
    
    Write-Success "CMake configuration complete"
}

function Invoke-Build {
    Write-Status "Building release binaries..."
    
    $parallelJobs = $env:NUMBER_OF_PROCESSORS
    
    & cmake --build . --parallel $parallelJobs --config $script:Config.BuildType
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed"
        exit 1
    }
    
    Write-Success "Build complete"
}

function Invoke-Tests {
    Write-Status "Running tests..."
    
    & ctest --output-on-failure -C $script:Config.BuildType
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Tests failed"
        exit 1
    }
    
    Write-Success "All tests passed"
}

function Invoke-Signing {
    if (-not $SignBinaries) {
        return
    }
    
    Write-Status "Signing binaries..."
    
    $binaries = Get-ChildItem -Path "." -Filter "*.exe" -Recurse
    $binaries += Get-ChildItem -Path "." -Filter "*.dll" -Recurse
    
    foreach ($binary in $binaries) {
        # Check if signtool is available
        $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
        if ($signtool) {
            & signtool.exe sign /fd SHA256 /a $binary.FullName
            Write-Success "Signed: $($binary.Name)"
        } else {
            Write-Warning "signtool.exe not found, skipping signing"
            break
        }
    }
}

function New-Package {
    if (-not $Package) {
        return
    }
    
    Write-Status "Creating distribution package..."
    
    $packageName = "RawrXD-v$($script:Config.Version)-win64"
    $packageDir = "$($script:Config.DistDir)\$packageName"
    
    New-Item -ItemType Directory -Path $packageDir -Force | Out-Null
    
    # Copy binaries
    $binDir = "$packageDir\bin"
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
    
    Get-ChildItem -Path "." -Filter "*.exe" -Recurse | Where-Object { 
        $_.FullName -notlike "*test*" -and $_.FullName -notlike "*example*" 
    } | ForEach-Object {
        Copy-Item $_.FullName $binDir
    }
    
    # Copy libraries
    $libDir = "$packageDir\lib"
    New-Item -ItemType Directory -Path $libDir -Force | Out-Null
    
    Get-ChildItem -Path "." -Filter "*.dll" -Recurse | ForEach-Object {
        Copy-Item $_.FullName $libDir
    }
    
    # Copy headers
    $includeDir = "$packageDir\include"
    Copy-Item -Recurse "..\include" $includeDir -ErrorAction SilentlyContinue
    
    # Copy documentation
    $docDir = "$packageDir\docs"
    New-Item -ItemType Directory -Path $docDir -Force | Out-Null
    
    @("README.md", "LICENSE", "CHANGELOG.md") | ForEach-Object {
        if (Test-Path "..\$_") {
            Copy-Item "..\$_" $docDir
        }
    }
    
    # Copy examples
    $examplesDir = "$packageDir\examples"
    Copy-Item -Recurse "..\examples" $examplesDir -ErrorAction SilentlyContinue
    
    # Create archive
    $archivePath = "$($script:Config.DistDir)\$packageName.zip"
    Compress-Archive -Path $packageDir -DestinationPath $archivePath -Force
    
    Write-Success "Package created: $archivePath"
    
    # Generate checksums
    $hash = Get-FileHash $archivePath -Algorithm SHA256
    "$($hash.Hash)  $packageName.zip" | Out-File "$($script:Config.DistDir)\checksums.txt"
    
    Write-Success "Checksums written to: $($script:Config.DistDir)\checksums.txt"
}

function Show-Summary {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Release Build Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Build Type: $($script:Config.BuildType)"
    Write-Host "Version: $($script:Config.Version)"
    Write-Host "CUDA: $EnableCUDA"
    Write-Host "Vulkan: $EnableVulkan"
    Write-Host "AVX-512: $EnableAVX512"
    Write-Host "Static Link: $StaticLink"
    Write-Host ""
    
    if ($Package) {
        Write-Host "Package Location: $($script:Config.DistDir)"
        Get-ChildItem $script:Config.DistDir | ForEach-Object {
            Write-Host "  - $($_.Name) ($([math]::Round($_.Length / 1MB, 2)) MB)"
        }
    }
    
    Write-Host ""
    Write-Success "Release build completed successfully!"
}

# Main execution
function Main {
    Write-Host "RawrXD Release Build Script" -ForegroundColor Cyan
    Write-Host "==========================" -ForegroundColor Cyan
    Write-Host ""
    
    $startTime = Get-Date
    
    try {
        Initialize-BuildEnvironment
        Invoke-Configure
        Invoke-Build
        Invoke-Tests
        Invoke-Signing
        New-Package
        Show-Summary
        
        $duration = (Get-Date) - $startTime
        Write-Host "`nTotal build time: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor Gray
    }
    catch {
        Write-Error "Build failed: $_"
        exit 1
    }
    finally {
        Set-Location ..
    }
}

Main
