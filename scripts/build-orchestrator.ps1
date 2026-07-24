# RawrXD Build Orchestrator
# Comprehensive build management with parallel execution, caching, and dependency tracking

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("full", "quick", "incremental", "clean", "release", "debug", "test", "package")]
    [string]$BuildType = "incremental",
    
    [string]$Target = "all",
    [int]$ParallelJobs = (Get-CimInstance Win32_Processor).NumberOfLogicalProcessors,
    [switch]$SkipTests,
    [switch]$SkipPackage,
    [switch]$ForceRebuild,
    [switch]$Verbose,
    [string]$LogLevel = "INFO"
)

$ErrorActionPreference = "Stop"

# Build configuration
$BuildConfig = @{
    RootDir = "D:\rawrxd"
    BuildDir = "D:\rawrxd\build"
    OutputDir = "D:\rawrxd\output"
    CacheDir = "D:\rawrxd\.buildcache"
    MaxRetries = 3
    TimeoutMinutes = 120
}

# Target definitions with dependencies
$BuildTargets = @{
    "core" = @{
        Name = "Core Kernel"
        CMakeTarget = "rawrxd_core"
        Dependencies = @()
        Priority = 1
        EstimatedTime = 300
    }
    "ggml" = @{
        Name = "GGML Backend"
        CMakeTarget = "ggml"
        Dependencies = @("core")
        Priority = 2
        EstimatedTime = 180
    }
    "gpu" = @{
        Name = "GPU Backend"
        CMakeTarget = "gpu_backend"
        Dependencies = @("ggml")
        Priority = 3
        EstimatedTime = 240
    }
    "vulkan" = @{
        Name = "Vulkan Backend"
        CMakeTarget = "vulkan_backend"
        Dependencies = @("gpu")
        Priority = 4
        EstimatedTime = 300
    }
    "cuda" = @{
        Name = "CUDA Backend"
        CMakeTarget = "cuda_backend"
        Dependencies = @("gpu")
        Priority = 4
        EstimatedTime = 360
    }
    "asm" = @{
        Name = "ASM Kernels"
        CMakeTarget = "asm_kernels"
        Dependencies = @("core")
        Priority = 2
        EstimatedTime = 120
    }
    "tests" = @{
        Name = "Test Suite"
        CMakeTarget = "test_suite"
        Dependencies = @("core", "ggml")
        Priority = 5
        EstimatedTime = 180
    }
    "cli" = @{
        Name = "CLI Tools"
        CMakeTarget = "rawrxd_cli"
        Dependencies = @("core", "ggml", "gpu")
        Priority = 6
        EstimatedTime = 120
    }
    "ide" = @{
        Name = "Win32 IDE"
        CMakeTarget = "Win32IDE"
        Dependencies = @("core", "ggml", "vulkan")
        Priority = 7
        EstimatedTime = 600
    }
}

# Initialize build state
$script:BuildState = @{
    StartTime = Get-Date
    CompletedTargets = @()
    FailedTargets = @()
    InProgress = @()
    CacheHits = 0
    CacheMisses = 0
    Warnings = @()
    Errors = @()
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[✗] $Message" -ForegroundColor Red }
function Write-Verbose { param([string]$Message) if ($Verbose) { Write-Host "[v] $Message" -ForegroundColor Gray } }

function Initialize-BuildEnvironment {
    Write-Status "Initializing build environment..."
    
    # Create directories
    foreach ($dir in @($BuildConfig.BuildDir, $BuildConfig.OutputDir, $BuildConfig.CacheDir)) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Verbose "Created directory: $dir"
        }
    }
    
    # Check prerequisites
    $prerequisites = @("cmake", "git", "cl")
    foreach ($prereq in $prerequisites) {
        $cmd = Get-Command $prereq -ErrorAction SilentlyContinue
        if (-not $cmd) {
            Write-Error "Prerequisite not found: $prereq"
            exit 1
        }
        Write-Verbose "Found prerequisite: $prereq"
    }
    
    # Load build cache
    $cacheFile = "$($BuildConfig.CacheDir)\build.cache"
    if (Test-Path $cacheFile) {
        $script:BuildCache = Get-Content $cacheFile | ConvertFrom-Json
    } else {
        $script:BuildCache = @{}
    }
    
    Write-Success "Build environment initialized"
}

function Get-TargetHash {
    param([string]$TargetName)
    
    $target = $BuildTargets[$TargetName]
    if (-not $target) { return $null }
    
    # Get source files for target
    $sourceFiles = @()
    $targetDir = "$($BuildConfig.RootDir)\src\$TargetName"
    if (Test-Path $targetDir) {
        $sourceFiles = Get-ChildItem -Path $targetDir -Recurse -File | 
            Where-Object { $_.Extension -in @(".cpp", ".h", ".hpp", ".c", ".asm") }
    }
    
    # Calculate hash from file contents and timestamps
    $hashString = ""
    foreach ($file in $sourceFiles | Sort-Object FullName) {
        $hashString += "$($file.FullName):$($file.LastWriteTimeUtc.Ticks):$($file.Length);"
    }
    
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hashString))
    return [BitConverter]::ToString($hashBytes).Replace("-", "").Substring(0, 16)
}

function Test-CacheHit {
    param([string]$TargetName)
    
    if ($ForceRebuild) { return $false }
    
    $currentHash = Get-TargetHash -TargetName $TargetName
    $cachedHash = $script:BuildCache[$TargetName]
    
    if ($cachedHash -and $cachedHash -eq $currentHash) {
        $script:BuildState.CacheHits++
        return $true
    }
    
    $script:BuildState.CacheMisses++
    return $false
}

function Update-Cache {
    param([string]$TargetName)
    
    $script:BuildCache[$TargetName] = Get-TargetHash -TargetName $TargetName
    $cacheFile = "$($BuildConfig.CacheDir)\build.cache"
    $script:BuildCache | ConvertTo-Json | Out-File $cacheFile
}

function Get-DependencyOrder {
    param([string[]]$TargetNames)
    
    $ordered = @()
    $visited = @{}
    $visiting = @{}
    
    function Visit-Target {
        param([string]$Name)
        
        if ($visiting[$Name]) {
            throw "Circular dependency detected: $Name"
        }
        
        if ($visited[$Name]) { return }
        
        $visiting[$Name] = $true
        
        $target = $BuildTargets[$Name]
        if ($target) {
            foreach ($dep in $target.Dependencies) {
                Visit-Target -Name $dep
            }
        }
        
        $visiting[$Name] = $false
        $visited[$Name] = $true
        $ordered += $Name
    }
    
    foreach ($target in $TargetNames) {
        Visit-Target -Name $target
    }
    
    return $ordered
}

function Invoke-TargetBuild {
    param([string]$TargetName)
    
    $target = $BuildTargets[$TargetName]
    if (-not $target) {
        Write-Error "Unknown target: $TargetName"
        return $false
    }
    
    # Check if already built
    if ($script:BuildState.CompletedTargets -contains $TargetName) {
        Write-Verbose "Target already built: $TargetName"
        return $true
    }
    
    # Check cache
    if (Test-CacheHit -TargetName $TargetName) {
        Write-Success "Cache hit for $TargetName - skipping build"
        $script:BuildState.CompletedTargets += $TargetName
        return $true
    }
    
    Write-Status "Building target: $($target.Name)"
    $script:BuildState.InProgress += $TargetName
    
    $startTime = Get-Date
    $success = $false
    $attempt = 0
    
    while ($attempt -lt $BuildConfig.MaxRetries -and -not $success) {
        $attempt++
        
        try {
            # Configure CMake if needed
            $buildType = if ($BuildType -eq "release") { "Release" } else { "Debug" }
            $cmakeArgs = @(
                "-S", $BuildConfig.RootDir,
                "-B", "$($BuildConfig.BuildDir)\$TargetName",
                "-DCMAKE_BUILD_TYPE=$buildType",
                "-DCMAKE_INSTALL_PREFIX=$($BuildConfig.OutputDir)"
            )
            
            if ($Verbose) {
                $cmakeArgs += "-DCMAKE_VERBOSE_MAKEFILE=ON"
            }
            
            $cmakeProcess = Start-Process -FilePath "cmake" -ArgumentList $cmakeArgs -Wait -PassThru -NoNewWindow
            if ($cmakeProcess.ExitCode -ne 0) {
                throw "CMake configuration failed for $TargetName"
            }
            
            # Build
            $buildArgs = @(
                "--build", "$($BuildConfig.BuildDir)\$TargetName",
                "--target", $target.CMakeTarget,
                "--parallel", $ParallelJobs
            )
            
            if ($Verbose) {
                $buildArgs += "--verbose"
            }
            
            $buildProcess = Start-Process -FilePath "cmake" -ArgumentList $buildArgs -Wait -PassThru -NoNewWindow
            if ($buildProcess.ExitCode -ne 0) {
                throw "Build failed for $TargetName"
            }
            
            $success = $true
            
        } catch {
            Write-Warning "Build attempt $attempt failed for $TargetName`: $_"
            if ($attempt -lt $BuildConfig.MaxRetries) {
                Write-Status "Retrying in 5 seconds..."
                Start-Sleep -Seconds 5
            }
        }
    }
    
    $duration = (Get-Date) - $startTime
    $script:BuildState.InProgress = $script:BuildState.InProgress | Where-Object { $_ -ne $TargetName }
    
    if ($success) {
        Write-Success "Built $($target.Name) in $($duration.ToString('mm\:ss'))"
        Update-Cache -TargetName $TargetName
        $script:BuildState.CompletedTargets += $TargetName
        return $true
    } else {
        Write-Error "Failed to build $TargetName after $($BuildConfig.MaxRetries) attempts"
        $script:BuildState.FailedTargets += $TargetName
        return $false
    }
}

function Invoke-Tests {
    if ($SkipTests) {
        Write-Status "Skipping tests (--SkipTests specified)"
        return $true
    }
    
    Write-Status "Running tests..."
    
    $testTargets = $BuildTargets.Keys | Where-Object { $BuildTargets[$_].Name -like "*Test*" -or $_ -eq "tests" }
    
    foreach ($testTarget in $testTargets) {
        if ($script:BuildState.CompletedTargets -contains $testTarget) {
            $testExe = "$($BuildConfig.BuildDir)\$testTarget\$testTarget.exe"
            if (Test-Path $testExe) {
                Write-Status "Running tests for $testTarget..."
                $testResult = & $testExe --gtest_output="xml:$($BuildConfig.OutputDir)\$testTarget-results.xml" 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Success "Tests passed for $testTarget"
                } else {
                    Write-Warning "Tests failed for $testTarget"
                    $script:BuildState.Warnings += "Test failures in $testTarget"
                }
            }
        }
    }
    
    return $true
}

function Invoke-Packaging {
    if ($SkipPackage) {
        Write-Status "Skipping packaging (--SkipPackage specified)"
        return $true
    }
    
    Write-Status "Creating release package..."
    
    $version = git describe --tags --always 2>$null
    if (-not $version) { $version = "dev-$(Get-Date -Format 'yyyyMMdd')" }
    
    $packageName = "rawrxd-$version-$BuildType"
    $packageDir = "$($BuildConfig.OutputDir)\$packageName"
    
    # Create package structure
    New-Item -ItemType Directory -Path $packageDir -Force | Out-Null
    New-Item -ItemType Directory -Path "$packageDir\bin" -Force | Out-Null
    New-Item -ItemType Directory -Path "$packageDir\lib" -Force | Out-Null
    New-Item -ItemType Directory -Path "$packageDir\include" -Force | Out-Null
    New-Item -ItemType Directory -Path "$packageDir\docs" -Force | Out-Null
    
    # Copy binaries
    Get-ChildItem -Path $BuildConfig.BuildDir -Recurse -Filter "*.exe" | ForEach-Object {
        Copy-Item $_.FullName "$packageDir\bin\" -ErrorAction SilentlyContinue
    }
    
    Get-ChildItem -Path $BuildConfig.BuildDir -Recurse -Filter "*.dll" | ForEach-Object {
        Copy-Item $_.FullName "$packageDir\bin\" -ErrorAction SilentlyContinue
    }
    
    # Copy headers
    Copy-Item "$($BuildConfig.RootDir)\include" "$packageDir\" -Recurse -ErrorAction SilentlyContinue
    
    # Create archive
    $archivePath = "$($BuildConfig.OutputDir)\$packageName.zip"
    Compress-Archive -Path $packageDir -DestinationPath $archivePath -Force
    
    Write-Success "Package created: $archivePath"
    return $true
}

function Show-BuildSummary {
    $totalTime = (Get-Date) - $script:BuildState.StartTime
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Build Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Build Type: $BuildType" -ForegroundColor White
    Write-Host "Total Time: $($totalTime.ToString('hh\:mm\:ss'))" -ForegroundColor White
    Write-Host ""
    Write-Host "Completed: $($script:BuildState.CompletedTargets.Count)" -ForegroundColor Green
    Write-Host "Failed: $($script:BuildState.FailedTargets.Count)" -ForegroundColor $(if ($script:BuildState.FailedTargets.Count -gt 0) { 'Red' } else { 'Green' })
    Write-Host "Cache Hits: $($script:BuildState.CacheHits)" -ForegroundColor Cyan
    Write-Host "Cache Misses: $($script:BuildState.CacheMisses)" -ForegroundColor Yellow
    
    if ($script:BuildState.Warnings.Count -gt 0) {
        Write-Host "`nWarnings:" -ForegroundColor Yellow
        foreach ($warning in $script:BuildState.Warnings) {
            Write-Host "  ! $warning" -ForegroundColor Yellow
        }
    }
    
    if ($script:BuildState.Errors.Count -gt 0) {
        Write-Host "`nErrors:" -ForegroundColor Red
        foreach ($error in $script:BuildState.Errors) {
            Write-Host "  ✗ $error" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    
    if ($script:BuildState.FailedTargets.Count -eq 0) {
        Write-Success "Build completed successfully!"
        return 0
    } else {
        Write-Error "Build completed with failures"
        return 1
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Build Orchestrator" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-BuildEnvironment
    
    # Determine targets to build
    $targetsToBuild = @()
    if ($Target -eq "all") {
        $targetsToBuild = $BuildTargets.Keys | Sort-Object { $BuildTargets[$_].Priority }
    } else {
        $targetsToBuild = $Target -split ","
    }
    
    # Resolve dependencies
    $orderedTargets = Get-DependencyOrder -TargetNames $targetsToBuild
    
    Write-Status "Build plan: $($orderedTargets -join ' -> ')"
    Write-Status "Parallel jobs: $ParallelJobs"
    Write-Host ""
    
    # Execute builds
    $allSuccess = $true
    foreach ($target in $orderedTargets) {
        $result = Invoke-TargetBuild -TargetName $target
        if (-not $result) {
            $allSuccess = $false
            if ($BuildType -ne "quick") {
                Write-Error "Stopping build due to failure in $target"
                break
            }
        }
    }
    
    # Run tests
    if ($allSuccess) {
        Invoke-Tests
    }
    
    # Package
    if ($allSuccess -and $BuildType -eq "release") {
        Invoke-Packaging
    }
    
    # Summary
    $exitCode = Show-BuildSummary
    exit $exitCode
}

Main
