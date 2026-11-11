# RawrXD Telemetry Build Script
# Compiles telemetry components and creates integration library

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("all", "telemetry", "integration", "test", "clean")]
    [string]$Target = "all",
    
    [switch]$Release,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# =============================================================================
# Configuration
# =============================================================================
$Config = @{
    Ml64Path = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
    LinkPath = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
    LibPath = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\lib.exe"
    
    SourceDir = "d:\RawrXD"
    OutputDir = "d:\RawrXD\telemetry-build"
    LibDir = "d:\RawrXD\telemetry-build\lib"
    IncDir = "d:\RawrXD\telemetry-build\include"
    
    # Source files
    TelemetryAsm = "RawrXD_Telemetry.asm"
    IntegrationAsm = "RawrXD_Sovereign_Telemetry_Integration.asm"
    ExportsAsm = "RawrXD_Telemetry_Exports.asm"
}

# =============================================================================
# Helper Functions
# =============================================================================
function Write-Header($text) {
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host $text -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Status($text, $type = "info") {
    switch ($type) {
        "success" { Write-Host "  ✓ $text" -ForegroundColor Green }
        "error" { Write-Host "  ✗ $text" -ForegroundColor Red }
        "warning" { Write-Host "  ⚠ $text" -ForegroundColor Yellow }
        "info" { Write-Host "  ℹ $text" -ForegroundColor Gray }
    }
}

function Test-ToolPath($path, $name) {
    if (-not (Test-Path $path)) {
        Write-Status "$name not found at $path" "error"
        return $false
    }
    return $true
}

function Initialize-BuildEnvironment {
    Write-Header "Initializing Build Environment"
    
    # Check tools
    $toolsOk = $true
    $toolsOk = $toolsOk -and (Test-ToolPath $Config.Ml64Path "ml64.exe")
    $toolsOk = $toolsOk -and (Test-ToolPath $Config.LinkPath "link.exe")
    $toolsOk = $toolsOk -and (Test-ToolPath $Config.LibPath "lib.exe")
    
    if (-not $toolsOk) {
        throw "Required build tools not found"
    }
    
    Write-Status "Build tools verified" "success"
    
    # Create output directories
    @($Config.OutputDir, $Config.LibDir, $Config.IncDir) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
            Write-Status "Created directory: $_" "info"
        }
    }
}

function Invoke-TelemetryBuild {
    Write-Header "Building RawrXD_Telemetry.asm"
    
    $sourceFile = Join-Path $Config.SourceDir $Config.TelemetryAsm
    if (-not (Test-Path $sourceFile)) {
        Write-Status "Source file not found: $sourceFile" "error"
        return $false
    }
    
    $objFile = Join-Path $Config.OutputDir "RawrXD_Telemetry.obj"
    
    $args = @(
        "/c",                           # Assemble only
        "/W3",                          # Warning level 3
        "/nologo",                     # No logo
        "/Zi",                          # Debug info
        "/Fo$objFile",                 # Output object
        $sourceFile
    )
    
    if ($Verbose) {
        Write-Status "Command: $($Config.Ml64Path) $($args -join ' ')" "info"
    }
    
    $proc = Start-Process -FilePath $Config.Ml64Path -ArgumentList $args -Wait -PassThru -NoNewWindow
    
    if ($proc.ExitCode -ne 0) {
        Write-Status "Assembly failed with exit code $($proc.ExitCode)" "error"
        return $false
    }
    
    if (-not (Test-Path $objFile)) {
        Write-Status "Object file not created: $objFile" "error"
        return $false
    }
    
    Write-Status "RawrXD_Telemetry.asm compiled successfully" "success"
    return $true
}

function Invoke-IntegrationBuild {
    Write-Header "Building Sovereign Telemetry Integration"
    
    $sourceFile = Join-Path $Config.SourceDir $Config.IntegrationAsm
    if (-not (Test-Path $sourceFile)) {
        Write-Status "Source file not found: $sourceFile" "error"
        return $false
    }
    
    $objFile = Join-Path $Config.OutputDir "RawrXD_Sovereign_Telemetry_Integration.obj"
    
    $args = @(
        "/c",
        "/W3",
        "/nologo",
        "/Zi",
        "/Fo$objFile",
        $sourceFile
    )
    
    if ($Verbose) {
        Write-Status "Command: $($Config.Ml64Path) $($args -join ' ')" "info"
    }
    
    $proc = Start-Process -FilePath $Config.Ml64Path -ArgumentList $args -Wait -PassThru -NoNewWindow
    
    if ($proc.ExitCode -ne 0) {
        Write-Status "Assembly failed with exit code $($proc.ExitCode)" "error"
        return $false
    }
    
    Write-Status "Sovereign_Telemetry_Integration.asm compiled successfully" "success"
    return $true
}

function Invoke-LibraryBuild {
    Write-Header "Creating Telemetry Library"
    
    $objFiles = @(
        Join-Path $Config.OutputDir "RawrXD_Telemetry.obj"
        Join-Path $Config.OutputDir "RawrXD_Sovereign_Telemetry_Integration.obj"
    )
    
    # Check all object files exist
    foreach ($obj in $objFiles) {
        if (-not (Test-Path $obj)) {
            Write-Status "Object file missing: $obj" "error"
            return $false
        }
    }
    
    $libFile = Join-Path $Config.LibDir "RawrXD_Telemetry.lib"
    
    $args = @(
        "/OUT:$libFile"
        "/NOLOGO"
    ) + $objFiles
    
    if ($Verbose) {
        Write-Status "Command: $($Config.LibPath) $($args -join ' ')" "info"
    }
    
    $proc = Start-Process -FilePath $Config.LibPath -ArgumentList $args -Wait -PassThru -NoNewWindow
    
    if ($proc.ExitCode -ne 0) {
        Write-Status "Library creation failed with exit code $($proc.ExitCode)" "error"
        return $false
    }
    
    if (-not (Test-Path $libFile)) {
        Write-Status "Library file not created: $libFile" "error"
        return $false
    }
    
    $libSize = (Get-Item $libFile).Length
    Write-Status "Library created: $libFile ($libSize bytes)" "success"
    
    return $true
}

function Copy-Headers {
    Write-Header "Copying Header Files"
    
    $headerFile = Join-Path $Config.SourceDir "RawrXD_Telemetry.h"
    if (Test-Path $headerFile) {
        Copy-Item $headerFile $Config.IncDir -Force
        Write-Status "Copied RawrXD_Telemetry.h to include directory" "success"
    } else {
        Write-Status "Header file not found: $headerFile" "warning"
    }
}

function Invoke-TestBuild {
    Write-Header "Building Test Harness"
    
    $testCode = @"
#include "RawrXD_Telemetry.h"
#include <stdio.h>
#include <windows.h>

int main() {
    printf("RawrXD Telemetry Test Harness\\n");
    printf("=============================\\n\\n");
    
    // Initialize telemetry
    printf("Initializing telemetry...\\n");
    if (!Sovereign_Telemetry_Init()) {
        printf("Failed to initialize telemetry\\n");
        return 1;
    }
    printf("Telemetry initialized successfully\\n\\n");
    
    // Simulate inference
    printf("Running test inference...\\n");
    int session = Sovereign_Inference_Begin(10);
    printf("Session started: %d\\n", session);
    
    // Generate some tokens
    for (int i = 0; i < 20; i++) {
        Sovereign_Token_Generated(100 + i, 15000 + (i * 100));
        
        // Simulate cache behavior
        if (i % 3 == 0) {
            SOVEREIGN_CACHE_MISS(i);
        } else {
            SOVEREIGN_CACHE_HIT(i);
        }
    }
    
    // Switch precision
    SOVEREIGN_USE_BF16();
    
    int tokens = Sovereign_Inference_End();
    printf("Inference complete: %d tokens generated\\n\\n", tokens);
    
    // Get stats
    TelemetryStats stats;
    Sovereign_GetTelemetryStats(&stats);
    
    printf("Telemetry Statistics:\\n");
    printf("  Total Inferences: %llu\\n", stats.total_inferences);
    printf("  Total Tokens: %llu\\n", stats.total_tokens);
    printf("  Avg Latency: %u us\\n", stats.avg_latency_us);
    printf("  Session Tokens: %u\\n", stats.current_session_tokens);
    printf("  Cache Hits: %u\\n", stats.session_cache_hits);
    printf("  Cache Misses: %u\\n", stats.session_cache_misses);
    printf("  Quant Type: %s\\n", 
        stats.current_quant_type == QUANT_INT8 ? "INT8" :
        stats.current_quant_type == QUANT_BF16 ? "BF16" : "FP32");
    
    printf("\\nTest completed successfully!\\n");
    return 0;
}
""@
    
    $testFile = Join-Path $Config.OutputDir "telemetry_test.c"
    $testCode | Out-File -FilePath $testFile -Encoding ASCII
    
    Write-Status "Created test harness: $testFile" "success"
}
    
    # Compile test
    $clPath = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
    if (Test-Path $clPath) {
        $exeFile = Join-Path $Config.OutputDir "telemetry_test.exe"
        
        $args = @(
            "/EHsc"
            "/nologo"
            "/Fe:$exeFile"
            "/I$($Config.IncDir)"
            $testFile
            "RawrXD_Telemetry.lib"
            "/link"
            "/LIBPATH:$($Config.LibDir)"
        )
        
        $proc = Start-Process -FilePath $clPath -ArgumentList $args -Wait -PassThru -NoNewWindow -WorkingDirectory $Config.OutputDir
        
        if ($proc.ExitCode -eq 0 -and (Test-Path $exeFile)) {
            Write-Status "Test harness compiled: $exeFile" "success"
            
            # Run test
            Write-Header "Running Telemetry Test"
            & $exeFile
        } else {
            Write-Status "Test compilation failed" "error"
        }
    } else {
        Write-Status "C++ compiler not found, skipping test build" "warning"
    }
}

function Clear-BuildOutput {
    Write-Header "Cleaning Build Output"
    
    if (Test-Path $Config.OutputDir) {
        Remove-Item $Config.OutputDir -Recurse -Force
        Write-Status "Removed build directory: $($Config.OutputDir)" "success"
    }
}

function Show-Summary {
    Write-Header "Build Summary"
    
    Write-Host "Output Directory: $($Config.OutputDir)" -ForegroundColor Yellow
    Write-Host ""
    
    if (Test-Path $Config.LibDir) {
        $libs = Get-ChildItem $Config.LibDir -Filter "*.lib"
        if ($libs) {
            Write-Host "Libraries:" -ForegroundColor Green
            $libs | ForEach-Object { Write-Host "  - $($_.Name) ($($_.Length) bytes)" }
        }
    }
    
    Write-Host ""
    
    if (Test-Path $Config.IncDir) {
        $headers = Get-ChildItem $Config.IncDir -Filter "*.h"
        if ($headers) {
            Write-Host "Headers:" -ForegroundColor Green
            $headers | ForEach-Object { Write-Host "  - $($_.Name)" }
        }
    }
    
    Write-Host ""
    Write-Host "Integration:" -ForegroundColor Yellow
    Write-Host "  C/C++: #include \"RawrXD_Telemetry.h\"" -ForegroundColor Gray
    Write-Host "  Link: RawrXD_Telemetry.lib" -ForegroundColor Gray
    Write-Host "  Path: -I$($Config.IncDir) -L$($Config.LibDir)" -ForegroundColor Gray
}

# =============================================================================
# Main Execution
# =============================================================================

switch ($Target.ToLower()) {
    "all" {
        Initialize-BuildEnvironment
        if (Invoke-TelemetryBuild) {
            if (Invoke-IntegrationBuild) {
                if (Invoke-LibraryBuild) {
                    Copy-Headers
                    Show-Summary
                }
            }
        }
    }
    "telemetry" {
        Initialize-BuildEnvironment
        Invoke-TelemetryBuild
    }
    "integration" {
        Initialize-BuildEnvironment
        Invoke-IntegrationBuild
    }
    "test" {
        Invoke-TestBuild
    }
    "clean" {
        Clear-BuildOutput
    }
    default {
        Write-Host "Usage: .\telemetry-build.ps1 -Target [all|telemetry|integration|test|clean]" -ForegroundColor Yellow
    }
}
