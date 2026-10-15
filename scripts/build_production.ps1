<#
.SYNOPSIS
    Production build script for RawrXD - builds with all security hardening enabled.

.DESCRIPTION
    This script configures and builds RawrXD with production-grade security hardening:
    - Compiler flags: /GS, /guard:cf, /DYNAMICBASE, /NXCOMPAT, /HIGHENTROPYVA, /SDL, /W4
    - Linker flags: /DYNAMICBASE, /NXCOMPAT, /HIGHENTROPYVA, /guard:cf
    - LTO: /GL /LTCG /OPT:REF /OPT:ICF
    - C++20 strict conformance (/permissive-)
    - AddressSanitizer support (optional)
    - SBOM generation

.PARAMETER Config
    Build configuration (Release, RelWithDebInfo, MinSizeRel). Default: Release

.PARAMETER Arch
    Target architecture (x64, ARM64). Default: x64

.PARAMETER EnableSanitizers
    Enable AddressSanitizer in Debug builds. Default: $false

.PARAMETER EnableLTO
    Enable Link Time Optimization. Default: $true

.PARAMETER OutputDir
    Custom output directory for artifacts

.PARAMETER SignArtifacts
    Sign build artifacts with code signing certificate. Default: $false

.PARAMETER CertThumbprint
    Certificate thumbprint for code signing (required if SignArtifacts=$true)

.EXAMPLE
    .\scripts\build_production.ps1 -Config Release -Arch x64

.EXAMPLE
    .\scripts\build_production.ps1 -Config Release -Arch x64 -SignArtifacts -CertThumbprint "ABC123..."
#>

param(
    [ValidateSet("Release", "RelWithDebInfo", "MinSizeRel", "Debug")]
    [string]$Config = "Release",

    [ValidateSet("x64", "ARM64")]
    [string]$Arch = "x64",

    [switch]$EnableSanitizers,

    [switch]$EnableLTO,

    [string]$OutputDir,

    [switch]$SignArtifacts,

    [string]$CertThumbprint
)

# Ensure we're in the repo root
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot

try {
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "RawrXD Production Build" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "Configuration: $Config"
    Write-Host "Architecture:  $Arch"
    Write-Host "Sanitizers:    $($EnableSanitizers.IsPresent)"
    Write-Host "LTO:           $($EnableLTO.IsPresent)"
    Write-Host ""

    # Clean stale build artifacts
    $buildDir = "build_prod"
    if (Test-Path -LiteralPath $buildDir) {
        Write-Host ">>> Cleaning previous build directory..." -ForegroundColor Yellow
        Remove-Item -LiteralPath $buildDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Ensure build directory exists
    New-Item -ItemType Directory -Path $buildDir -Force | Out-Null

    # Build CMake arguments
    $cmakeArgs = @(
        "-S", ".",
        "-B", $buildDir,
        "-A", $Arch,
        "-DCMAKE_BUILD_TYPE=$Config",
        "-DRAWRXD_ENABLE_HARDENING=ON",
        "-DRAWRXD_ENABLE_LTO=$([bool]$EnableLTO.IsPresent)",
        "-DRAWRXD_BUILD_WIN32IDE=ON",
        "-DRAWRXD_BUILD_TESTS=ON",
        "-DENABLE_VULKAN=OFF",
        "-DGGML_VULKAN=OFF",
        "-DCMAKE_CXX_STANDARD=20",
        "-DCMAKE_CXX_STANDARD_REQUIRED=ON",
        "-DCMAKE_CXX_EXTENSIONS=OFF"
    )

    if ($EnableSanitizers.IsPresent) {
        $cmakeArgs += "-DRAWRXD_ENABLE_SANITIZERS=ON"
        Write-Host ">>> Sanitizers ENABLED for Debug builds" -ForegroundColor Green
    }

    # Add output directory if specified
    if ($OutputDir) {
        $cmakeArgs += "-DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$OutputDir"
        $cmakeArgs += "-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=$OutputDir"
        $cmakeArgs += "-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=$OutputDir"
    }

    Write-Host ">>> Configuring CMake with production hardening..." -ForegroundColor Cyan
    Write-Host "cmake $($cmakeArgs -join ' ')" -ForegroundColor Gray
    & cmake @cmakeArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Error "CMake configure failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }

    Write-Host ">>> Building..." -ForegroundColor Cyan
    & cmake --build $buildDir --config $Config --parallel
    if ($LASTEXITCODE -ne 0) {
        Write-Error "CMake build failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }

    Write-Host ">>> Build successful!" -ForegroundColor Green

    # Find built executables
    $binDir = "$buildDir\bin\$Config"
    if (-not (Test-Path -LiteralPath $binDir)) {
        $binDir = "$buildDir\bin"
    }

    $executables = Get-ChildItem -LiteralPath $binDir -Filter "*.exe" -ErrorAction SilentlyContinue
    $dlls = Get-ChildItem -LiteralPath $binDir -Filter "*.dll" -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host ">>> Built artifacts:" -ForegroundColor Cyan
    foreach ($exe in $executables) {
        Write-Host "  $($exe.Name) ($("{0:N0}" -f $exe.Length) bytes)" -ForegroundColor Green
    }
    foreach ($dll in $dlls) {
        Write-Host "  $($dll.Name) ($("{0:N0}" -f $dll.Length) bytes)" -ForegroundColor Gray
    }

    # Code signing if requested
    if ($SignArtifacts.IsPresent) {
        if (-not $CertThumbprint) {
            Write-Error "SignArtifacts requires -CertThumbprint parameter"
            exit 1
        }

        Write-Host ">>> Signing artifacts with certificate $CertThumbprint..." -ForegroundColor Cyan
        $signTool = "signtool.exe"
        $signArgs = @("sign", "/fd", "SHA256", "/sha1", $CertThumbprint, "/tr", "http://timestamp.digicert.com", "/td", "SHA256")

        foreach ($exe in $executables) {
            & $signTool @signArgs $exe.FullName
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Failed to sign $($exe.Name)"
            } else {
                Write-Host "  Signed: $($exe.Name)" -ForegroundColor Green
            }
        }

        foreach ($dll in $dlls) {
            & $signTool @signArgs $dll.FullName
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Failed to sign $($dll.Name)"
            } else {
                Write-Host "  Signed: $($dll.Name)" -ForegroundColor Green
            }
        }
    }

    # Generate SBOM (Software Bill of Materials)
    Write-Host ">>> Generating SBOM..." -ForegroundColor Cyan
    $sbomPath = "$buildDir\sbom.json"
    $sbom = @{
        name = "RawrXD"
        version = "1.0.13"
        buildDate = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        gitCommit = (git rev-parse HEAD 2>$null)
        gitBranch = (git branch --show-current 2>$null)
        configuration = $Config
        architecture = $Arch
        hardening = @{
            compilerFlags = @("/GS", "/guard:cf", "/DYNAMICBASE", "/NXCOMPAT", "/HIGHENTROPYVA", "/SDL", "/W4", "/permissive-")
            linkerFlags = @("/DYNAMICBASE", "/NXCOMPAT", "/HIGHENTROPYVA", "/guard:cf", "/LTCG", "/OPT:REF", "/OPT:ICF")
            lto = $EnableLTO.IsPresent
            sanitizers = $EnableSanitizers.IsPresent
        }
        executables = $executables | ForEach-Object { @{ name = $_.Name; size = $_.Length; sha256 = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash } }
        libraries = $dlls | ForEach-Object { @{ name = $_.Name; size = $_.Length; sha256 = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash } }
    }
    $sbom | ConvertTo-Json -Depth 5 | Out-File -FilePath $sbomPath -Encoding utf8
    Write-Host "  SBOM written to $sbomPath" -ForegroundColor Green

    # Generate build manifest
    $manifestPath = "$buildDir\build_manifest.json"
    $manifest = @{
        project = "RawrXD"
        version = "1.0.13"
        buildDate = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        gitCommit = (git rev-parse HEAD 2>$null)
        gitBranch = (git branch --show-current 2>$null)
        configuration = $Config
        architecture = $Arch
        buildMachine = $env:COMPUTERNAME
        buildUser = $env:USERNAME
        cmakeGenerator = "Visual Studio 17 2022"
        cmakeArgs = $cmakeArgs
        artifacts = @(
            $executables | ForEach-Object { @{ path = $_.FullName; name = $_.Name; size = $_.Length; sha256 = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash } },
            $dlls | ForEach-Object { @{ path = $_.FullName; name = $_.Name; size = $_.Length; sha256 = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash } }
        )
    }
    $manifest | ConvertTo-Json -Depth 5 | Out-File -FilePath $manifestPath -Encoding utf8
    Write-Host "  Build manifest written to $manifestPath" -ForegroundColor Green

    # Create release package if output directory specified
    if ($OutputDir) {
        Write-Host ">>> Creating release package..." -ForegroundColor Cyan
        $pkgDir = "$OutputDir\RawrXD-$Config-$Arch"
        if (Test-Path -LiteralPath $pkgDir) {
            Remove-Item -LiteralPath $pkgDir -Recurse -Force
        }
        New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null

        foreach ($exe in $executables) {
            Copy-Item -LiteralPath $exe.FullName -Destination "$pkgDir\$($exe.Name)" -Force
        }
        foreach ($dll in $dlls) {
            Copy-Item -LiteralPath $dll.FullName -Destination "$pkgDir\$($dll.Name)" -Force
        }
        Copy-Item -LiteralPath $sbomPath -Destination "$pkgDir\sbom.json" -Force
        Copy-Item -LiteralPath $manifestPath -Destination "$pkgDir\build_manifest.json" -Force

        # Create zip archive
        $zipPath = "$OutputDir\RawrXD-$Config-$Arch.zip"
        if (Test-Path -LiteralPath $zipPath) {
            Remove-Item -LiteralPath $zipPath -Force
        }
        & 7z a -tzip $zipPath "$pkgDir\*"
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  Release package: $zipPath" -ForegroundColor Green
        } else {
            Write-Warning "Failed to create zip archive (7z not found?)"
        }
    }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "PRODUCTION BUILD COMPLETE" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "Binaries: $binDir"
    Write-Host "SBOM:     $sbomPath"
    Write-Host "Manifest: $manifestPath"

}
finally {
    Pop-Location
}