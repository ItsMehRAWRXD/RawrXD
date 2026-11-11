#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Build Matrix Generator for RawrXD CI/CD

.DESCRIPTION
    Generates build matrix configurations for CI/CD pipelines:
    - GitHub Actions matrix
    - Azure DevOps matrix
    - Docker build matrix
    - Cross-platform build configurations

.EXAMPLE
    .\scripts\generate_build_matrix.ps1
    .\scripts\generate_build_matrix.ps1 -Platform github
    .\scripts\generate_build_matrix.ps1 -Output .github/workflows/matrix.json

.NOTES
    Part of RawrXD Phase AB: CI/CD Pipeline & Automation
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet("github", "azure", "docker", "all")]
    [string]$Platform = "all",

    [Parameter()]
    [string]$OutputPath = "",

    [Parameter()]
    [switch]$IncludeExperimental,

    [Parameter()]
    [switch]$MinimizeMatrix
)

# ============================================================================
# Build Matrix Configuration
# ============================================================================

$BuildMatrix = @{
    # Operating Systems
    OS = @(
        @{ Name = "windows"; Runner = "windows-latest"; Container = $null }
        @{ Name = "linux"; Runner = "ubuntu-latest"; Container = $null }
        @{ Name = "macos"; Runner = "macos-latest"; Container = $null }
    )

    # Compilers
    Compilers = @(
        @{ Name = "msvc"; Version = "2022"; CC = "cl"; CXX = "cl"; OS = @("windows") }
        @{ Name = "gcc"; Version = "12"; CC = "gcc"; CXX = "g++"; OS = @("linux") }
        @{ Name = "gcc"; Version = "13"; CC = "gcc-13"; CXX = "g++-13"; OS = @("linux"); Experimental = $true }
        @{ Name = "clang"; Version = "16"; CC = "clang"; CXX = "clang++"; OS = @("linux", "macos") }
        @{ Name = "clang"; Version = "17"; CC = "clang-17"; CXX = "clang++-17"; OS = @("linux"); Experimental = $true }
    )

    # Build Types
    BuildTypes = @(
        @{ Name = "Release"; CMakeFlags = "-DCMAKE_BUILD_TYPE=Release" }
        @{ Name = "Debug"; CMakeFlags = "-DCMAKE_BUILD_TYPE=Debug" }
        @{ Name = "RelWithDebInfo"; CMakeFlags = "-DCMAKE_BUILD_TYPE=RelWithDebInfo" }
    )

    # Features
    Features = @(
        @{ Name = "default"; Flags = ""; Description = "Default configuration" }
        @{ Name = "vulkan"; Flags = "-DRAWRXD_VULKAN=ON"; Description = "With Vulkan support" }
        @{ Name = "cuda"; Flags = "-DRAWRXD_CUDA=ON"; Description = "With CUDA support"; OS = @("linux", "windows") }
        @{ Name = "rocm"; Flags = "-DRAWRXD_ROCM=ON"; Description = "With ROCm support"; OS = @("linux"); Experimental = $true }
        @{ Name = "metal"; Flags = "-DRAWRXD_METAL=ON"; Description = "With Metal support"; OS = @("macos") }
        @{ Name = "minimal"; Flags = "-DRAWRXD_MINIMAL=ON"; Description = "Minimal build" }
    )

    # Architectures
    Architectures = @(
        @{ Name = "x64"; CMakeFlags = "-A x64" }
        @{ Name = "arm64"; CMakeFlags = "-A ARM64"; Experimental = $true }
    )
}

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Test-ValidCombination {
    param($OS, $Compiler, $Feature)

    # Check OS compatibility
    if ($Compiler.OS -and -not ($Compiler.OS -contains $OS.Name)) {
        return $false
    }

    # Check feature OS compatibility
    if ($Feature.OS -and -not ($Feature.OS -contains $OS.Name)) {
        return $false
    }

    # Skip experimental unless explicitly included
    if (($Compiler.Experimental -or $Feature.Experimental) -and -not $IncludeExperimental) {
        return $false
    }

    return $true
}

# ============================================================================
# Matrix Generators
# ============================================================================

function Get-GitHubMatrix {
    $matrix = @{
        include = @()
    }

    foreach ($os in $BuildMatrix.OS) {
        foreach ($compiler in $BuildMatrix.Compilers) {
            foreach ($buildType in $BuildMatrix.BuildTypes) {
                foreach ($feature in $BuildMatrix.Features) {
                    if (-not (Test-ValidCombination $os $compiler $feature)) {
                        continue
                    }

                    $config = [ordered]@{
                        name = "$($os.Name)-$($compiler.Name)$($compiler.Version)-$($buildType.Name)-$($feature.Name)"
                        os = $os.Runner
                        compiler = $compiler.Name
                        compiler_version = $compiler.Version
                        cc = $compiler.CC
                        cxx = $compiler.CXX
                        build_type = $buildType.Name
                        cmake_flags = "$($buildType.CMakeFlags) $($feature.Flags)".Trim()
                        feature = $feature.Name
                    }

                    $matrix.include += $config
                }
            }
        }
    }

    return $matrix
}

function Get-AzureMatrix {
    $matrix = @{}

    foreach ($os in $BuildMatrix.OS) {
        foreach ($compiler in $BuildMatrix.Compilers) {
            foreach ($buildType in $BuildMatrix.BuildTypes) {
                foreach ($feature in $BuildMatrix.Features) {
                    if (-not (Test-ValidCombination $os $compiler $feature)) {
                        continue
                    }

                    $key = "$($os.Name)_$($compiler.Name)$($compiler.Version)_$($buildType.Name)_$($feature.Name)"
                    $matrix[$key] = [ordered]@{
                        VMImage = switch ($os.Name) {
                            "windows" { "windows-2022" }
                            "linux" { "ubuntu-latest" }
                            "macos" { "macos-latest" }
                        }
                        Compiler = $compiler.Name
                        CompilerVersion = $compiler.Version
                        CC = $compiler.CC
                        CXX = $compiler.CXX
                        BuildType = $buildType.Name
                        CMakeFlags = "$($buildType.CMakeFlags) $($feature.Flags)".Trim()
                        Feature = $feature.Name
                    }
                }
            }
        }
    }

    return $matrix
}

function Get-DockerMatrix {
    $matrix = @{
        images = @()
    }

    $baseImages = @(
        @{ Tag = "ubuntu-22.04"; Base = "ubuntu:22.04"; Platform = "linux/amd64" }
        @{ Tag = "ubuntu-22.04-cuda"; Base = "nvidia/cuda:12.0-devel-ubuntu22.04"; Platform = "linux/amd64"; Feature = "cuda" }
        @{ Tag = "windows-2022"; Base = "mcr.microsoft.com/windows/servercore:ltsc2022"; Platform = "windows/amd64" }
    )

    foreach ($image in $baseImages) {
        foreach ($buildType in $BuildMatrix.BuildTypes) {
            $config = [ordered]@{
                tag = "$($image.Tag)-$($buildType.Name.ToLower())"
                base = $image.Base
                platform = $image.Platform
                build_type = $buildType.Name
                cmake_flags = $buildType.CMakeFlags
            }

            if ($image.Feature) {
                $config.feature = $image.Feature
            }

            $matrix.images += $config
        }
    }

    return $matrix
}

function Get-MinimizedMatrix {
    # Generate a minimal matrix for quick CI runs
    return @{
        include = @(
            @{ name = "windows-msvc-release"; os = "windows-latest"; compiler = "msvc"; build_type = "Release" }
            @{ name = "linux-gcc-release"; os = "ubuntu-latest"; compiler = "gcc"; build_type = "Release" }
            @{ name = "macos-clang-release"; os = "macos-latest"; compiler = "clang"; build_type = "Release" }
            @{ name = "windows-msvc-debug"; os = "windows-latest"; compiler = "msvc"; build_type = "Debug" }
        )
    }
}

# ============================================================================
# Output Formatters
# ============================================================================

function Write-GitHubOutput {
    param($Matrix)

    $output = @"
# Generated GitHub Actions Build Matrix
# Auto-generated by generate_build_matrix.ps1
# Timestamp: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

strategy:
  fail-fast: false
  matrix:
    include:
"@

    foreach ($config in $Matrix.include) {
        $output += "`n      - name: $($config.name)`n"
        foreach ($key in $config.Keys) {
            if ($key -ne "name") {
                $output += "        $key: $($config[$key])`n"
            }
        }
    }

    return $output
}

function Write-AzureOutput {
    param($Matrix)

    $output = @"
# Generated Azure DevOps Build Matrix
# Auto-generated by generate_build_matrix.ps1
# Timestamp: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

jobs:
"@

    foreach ($key in $Matrix.Keys) {
        $config = $Matrix[$key]
        $output += "`n  - job: $key`n"
        $output += "    pool:`n"
        $output += "      vmImage: $($config.VMImage)`n"
        $output += "    variables:`n"
        $output += "      CC: $($config.CC)`n"
        $output += "      CXX: $($config.CXX)`n"
        $output += "      CMAKE_FLAGS: $($config.CMakeFlags)`n"
    }

    return $output
}

function Write-DockerOutput {
    param($Matrix)

    $output = @"
# Generated Docker Build Matrix
# Auto-generated by generate_build_matrix.ps1
# Timestamp: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

# Build all images
"@

    foreach ($image in $Matrix.images) {
        $output += "`n# $($image.tag)`n"
        $output += "docker build `
        $output += "  --platform $($image.platform) `
        $output += "  --build-arg BASE_IMAGE=$($image.base) `
        $output += "  --build-arg BUILD_TYPE=$($image.build_type) `
        $output += "  --build-arg CMAKE_FLAGS=`"$($image.cmake_flags)`" `
        $output += "  -t rawrxd:$($image.tag) .
"
    }

    return $output
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Build Matrix Generator" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    $results = @{}

    if ($MinimizeMatrix) {
        Write-Status "Generating minimized matrix..." "Info"
        $results["github"] = Get-MinimizedMatrix
    } else {
        if ($Platform -in @("github", "all")) {
            Write-Status "Generating GitHub Actions matrix..." "Info"
            $results["github"] = Get-GitHubMatrix
        }

        if ($Platform -in @("azure", "all")) {
            Write-Status "Generating Azure DevOps matrix..." "Info"
            $results["azure"] = Get-AzureMatrix
        }

        if ($Platform -in @("docker", "all")) {
            Write-Status "Generating Docker matrix..." "Info"
            $results["docker"] = Get-DockerMatrix
        }
    }

    # Output results
    if ($OutputPath) {
        $json = $results | ConvertTo-Json -Depth 10
        $json | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Status "Matrix written to $OutputPath" "Success"
    } else {
        # Print to console
        foreach ($platformName in $results.Keys) {
            Write-Host "`n========================================" -ForegroundColor Yellow
            Write-Host "$platformName Matrix" -ForegroundColor Yellow
            Write-Host "========================================" -ForegroundColor Yellow

            switch ($platformName) {
                "github" { Write-Host (Write-GitHubOutput $results[$platformName]) }
                "azure" { Write-Host (Write-AzureOutput $results[$platformName]) }
                "docker" { Write-Host (Write-DockerOutput $results[$platformName]) }
            }
        }
    }

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    foreach ($platformName in $results.Keys) {
        $count = switch ($platformName) {
            "github" { $results[$platformName].include.Count }
            "azure" { $results[$platformName].Count }
            "docker" { $results[$platformName].images.Count }
        }
        Write-Host "  $platformName`: $count configurations" -ForegroundColor White
    }

    Write-Status "Build matrix generation complete!" "Success"
}

# Run main
Main
