#!/usr/bin/env pwsh
# ============================================================================
# MASM_Build_Automation.ps1
# Purpose: Automated MASM x64 build pipeline with hotpatch integration
# Features: Incremental builds, dependency tracking, AVX-512 optimization
# ============================================================================

param(
    [string]$SourceDir = "..\src\asm",
    [string]$OutputDir = "..\build",
    [string]$ML64Path = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe",
    [string]$LinkPath = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe",
    [switch]$Clean = $false,
    [switch]$Parallel = $true,
    [int]$MaxParallelJobs = 4,
    [switch]$EnableHotpatch = $true,
    [switch]$Benchmark = $false
)

$ErrorActionPreference = "Stop"

# ═══════════════════════════════════════════════════════════════════════════
# Build Configuration
# ═══════════════════════════════════════════════════════════════════════════

$BuildConfig = @{
    ML64Flags = "/c /W3 /nologo /Zi /DWIN64 /DAVX512_SUPPORTED"
    LinkFlags = "/SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /NODEFAULTLIB /LARGEADDRESSAWARE:NO"
    Optimization = @{
        AVX512 = $true
        ParallelBuild = $Parallel
        Incremental = $true
    }
    Hotpatch = @{
        Enabled = $EnableHotpatch
        Layers = @(1, 2, 5)  # Memory, Byte, LiveBinary
    }
}

$BuildState = @{
    StartTime = Get-Date
    TotalFiles = 0
    BuiltFiles = 0
    FailedFiles = 0
    SkippedFiles = 0
    Warnings = @()
    Errors = @()
}

# ═══════════════════════════════════════════════════════════════════════════
# Build Engine
# ═══════════════════════════════════════════════════════════════════════════

function Initialize-BuildEnvironment {
    Write-Host "[BUILD] Initializing MASM x64 Build Environment" -ForegroundColor Cyan
    
    # Verify tools exist
    if (-not (Test-Path $ML64Path)) {
        throw "ml64.exe not found at: $ML64Path"
    }
    if (-not (Test-Path $LinkPath)) {
        throw "link.exe not found at: $LinkPath"
    }
    
    # Create output directory
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    
    # Clean if requested
    if ($Clean) {
        Write-Host "[BUILD] Cleaning output directory..." -ForegroundColor Yellow
        Remove-Item "$OutputDir\*" -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # Create subdirectories
    @("obj", "bin", "pdb", "hotpatch") | ForEach-Object {
        $dir = Join-Path $OutputDir $_
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
    
    Write-Host "[BUILD] Source: $SourceDir" -ForegroundColor Gray
    Write-Host "[BUILD] Output: $OutputDir" -ForegroundColor Gray
    Write-Host "[BUILD] ML64: $ML64Path" -ForegroundColor Gray
    Write-Host "[BUILD] Parallel: $Parallel (Jobs: $MaxParallelJobs)" -ForegroundColor Gray
    Write-Host "[BUILD] AVX-512: $($BuildConfig.Optimization.AVX512)" -ForegroundColor Gray
    Write-Host "[BUILD] Hotpatch: $($BuildConfig.Hotpatch.Enabled)" -ForegroundColor Gray
}

function Get-AssemblyFiles {
    $files = Get-ChildItem -Path $SourceDir -Filter "*.asm" -Recurse
    $BuildState.TotalFiles = $files.Count
    return $files
}

function Test-NeedsRebuild {
    param([System.IO.FileInfo]$SourceFile)
    
    if (-not $BuildConfig.Optimization.Incremental) {
        return $true
    }
    
    $objFile = Join-Path "$OutputDir\obj" ([System.IO.Path]::ChangeExtension($SourceFile.Name, ".obj"))
    
    if (-not (Test-Path $objFile)) {
        return $true
    }
    
    $sourceTime = $SourceFile.LastWriteTime
    $objTime = (Get-Item $objFile).LastWriteTime
    
    return $sourceTime -gt $objTime
}

function Invoke-MASMCompile {
    param([System.IO.FileInfo]$SourceFile)
    
    $objFile = Join-Path "$OutputDir\obj" ([System.IO.Path]::ChangeExtension($SourceFile.Name, ".obj"))
    $pdbFile = Join-Path "$OutputDir\pdb" ([System.IO.Path]::ChangeExtension($SourceFile.Name, ".pdb"))
    
    # Build flags
    $flags = $BuildConfig.ML64Flags
    if ($BuildConfig.Optimization.AVX512) {
        $flags += " /arch:AVX512"
    }
    
    $args = "$flags /Fo `"$objFile`" /Fd `"$pdbFile`" `"$($SourceFile.FullName)`""
    
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        $output = & $ML64Path @($flags.Split()) /Fo $objFile /Fd $pdbFile $SourceFile.FullName 2>&1
        $sw.Stop()
        
        if ($LASTEXITCODE -ne 0) {
            throw "Compilation failed with exit code $LASTEXITCODE"
        }
        
        # Check for warnings
        if ($output -match "warning") {
            $BuildState.Warnings += @{
                File = $SourceFile.Name
                Message = $output
            }
        }
        
        return @{
            Success = $true
            Duration = $sw.Elapsed
            Output = $objFile
        }
    }
    catch {
        $sw.Stop()
        $BuildState.Errors += @{
            File = $SourceFile.Name
            Message = $_.Exception.Message
        }
        return @{
            Success = $false
            Duration = $sw.Elapsed
            Error = $_.Exception.Message
        }
    }
}

function Start-ParallelBuild {
    param([array]$Files)
    
    Write-Host "[BUILD] Starting parallel build ($MaxParallelParallelJobs jobs)..." -ForegroundColor Cyan
    
    $jobs = @()
    $completed = 0
    
    foreach ($file in $Files) {
        # Wait if max jobs reached
        while ((Get-Job -State Running).Count -ge $MaxParallelJobs) {
            Start-Sleep -Milliseconds 100
        }
        
        $job = Start-Job -ScriptBlock {
            param($filePath, $ml64, $flags, $outDir)
            
            $file = Get-Item $filePath
            $objFile = Join-Path "$outDir\obj" ([System.IO.Path]::ChangeExtension($file.Name, ".obj"))
            $pdbFile = Join-Path "$outDir\pdb" ([System.IO.Path]::ChangeExtension($file.Name, ".pdb"))
            
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $output = & $ml64 @($flags.Split()) /Fo $objFile /Fd $pdbFile $file.FullName 2>&1
            $sw.Stop()
            
            return @{
                File = $file.Name
                Success = $LASTEXITCODE -eq 0
                Duration = $sw.Elapsed
                Output = $objFile
                ErrorOutput = $output
            }
        } -ArgumentList $file.FullName, $ML64Path, $BuildConfig.ML64Flags, $OutputDir
        
        $jobs += $job
    }
    
    # Wait for all jobs
    $jobs | Wait-Job | Out-Null
    
    # Collect results
    foreach ($job in $jobs) {
        $result = Receive-Job $job
        Remove-Job $job
        
        if ($result.Success) {
            $BuildState.BuiltFiles++
            Write-Host "  [OK] $($result.File) ($([math]::Round($result.Duration.TotalMilliseconds, 1)) ms)" -ForegroundColor Green
        }
        else {
            $BuildState.FailedFiles++
            Write-Host "  [FAIL] $($result.File)" -ForegroundColor Red
            $BuildState.Errors += @{
                File = $result.File
                Message = $result.ErrorOutput
            }
        }
    }
}

function Start-SerialBuild {
    param([array]$Files)
    
    Write-Host "[BUILD] Starting serial build..." -ForegroundColor Cyan
    
    foreach ($file in $Files) {
        $result = Invoke-MASMCompile -SourceFile $file
        
        if ($result.Success) {
            $BuildState.BuiltFiles++
            Write-Host "  [OK] $($file.Name) ($([math]::Round($result.Duration.TotalMilliseconds, 1)) ms)" -ForegroundColor Green
        }
        else {
            $BuildState.FailedFiles++
            Write-Host "  [FAIL] $($file.Name)" -ForegroundColor Red
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════
# Hotpatch Integration
# ═══════════════════════════════════════════════════════════════════════════

function Invoke-HotpatchGeneration {
    if (-not $BuildConfig.Hotpatch.Enabled) {
        return
    }
    
    Write-Host "`n[HOTPATCH] Generating hotpatch metadata..." -ForegroundColor Cyan
    
    $hotpatchDir = Join-Path $OutputDir "hotpatch"
    
    # Generate symbol table
    $symbols = @()
    $objFiles = Get-ChildItem -Path "$OutputDir\obj" -Filter "*.obj"
    
    foreach ($obj in $objFiles) {
        # Extract symbols (simplified - in production use dumpbin)
        $symbols += @{
            Object = $obj.Name
            Symbols = @(
                "AudioBuffer_Create",
                "AudioBuffer_Write",
                "VAD_ProcessBuffer",
                "Resampler_Process"
            )
        }
    }
    
    # Generate hotpatch manifest
    $manifest = @{
        version = "1.0"
        build_timestamp = Get-Date -Format "o"
        layers = @()
        symbols = $symbols
    }
    
    foreach ($layer in $BuildConfig.Hotpatch.Layers) {
        $layerInfo = switch ($layer) {
            1 { @{ id = 1; name = "Memory"; enabled = $true } }
            2 { @{ id = 2; name = "Byte"; enabled = $true } }
            5 { @{ id = 5; name = "LiveBinary"; enabled = $true } }
        }
        $manifest.layers += $layerInfo
    }
    
    $manifestPath = Join-Path $hotpatchDir "hotpatch_manifest.json"
    $manifest | ConvertTo-Json -Depth 10 | Set-Content $manifestPath
    
    Write-Host "[HOTPATCH] Manifest: $manifestPath" -ForegroundColor Green
    Write-Host "[HOTPATCH] Layers: $($manifest.layers.Count)" -ForegroundColor Green
    Write-Host "[HOTPATCH] Symbols: $($symbols.Count) objects" -ForegroundColor Green
}

# ═══════════════════════════════════════════════════════════════════════════
# Linking
# ═══════════════════════════════════════════════════════════════════════════

function Start-Linking {
    Write-Host "`n[LINK] Starting link phase..." -ForegroundColor Cyan
    
    $objFiles = Get-ChildItem -Path "$OutputDir\obj" -Filter "*.obj" | Select-Object -ExpandProperty FullName
    
    if ($objFiles.Count -eq 0) {
        Write-Host "[LINK] No object files to link" -ForegroundColor Yellow
        return
    }
    
    $exeFile = Join-Path "$OutputDir\bin" "AudioEngine.exe"
    $mapFile = Join-Path "$OutputDir" "AudioEngine.map"
    
    $linkArgs = @(
        $BuildConfig.LinkFlags.Split()
        "/OUT:`"$exeFile`""
        "/MAP:`"$mapFile`""
    ) + $objFiles
    
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        $output = & $LinkPath $linkArgs 2>&1
        $sw.Stop()
        
        if ($LASTEXITCODE -ne 0) {
            throw "Link failed with exit code $LASTEXITCODE"
        }
        
        Write-Host "[LINK] Success: $exeFile" -ForegroundColor Green
        Write-Host "[LINK] Duration: $([math]::Round($sw.Elapsed.TotalMilliseconds, 1)) ms" -ForegroundColor Gray
        
        # Show size
        $exeInfo = Get-Item $exeFile
        Write-Host "[LINK] Size: $([math]::Round($exeInfo.Length / 1KB, 2)) KB" -ForegroundColor Gray
    }
    catch {
        $sw.Stop()
        Write-Host "[LINK] Failed: $_" -ForegroundColor Red
        $BuildState.Errors += @{
            File = "LINK"
            Message = $_.Exception.Message
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════
# Benchmark Mode
# ═══════════════════════════════════════════════════════════════════════════

function Start-BuildBenchmark {
    Write-Host "`n[BENCHMARK] Running build performance benchmark..." -ForegroundColor Cyan
    
    $iterations = 5
    $times = @()
    
    for ($i = 1; $i -le $iterations; $i++) {
        Write-Host "  Iteration $i/$iterations..." -ForegroundColor Gray
        
        # Clean and rebuild
        Remove-Item "$OutputDir\obj\*" -Force -ErrorAction SilentlyContinue
        
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        
        $files = Get-AssemblyFiles
        if ($Parallel) {
            Start-ParallelBuild -Files $files
        }
        else {
            Start-SerialBuild -Files $files
        }
        
        $sw.Stop()
        $times += $sw.Elapsed
        
        Write-Host "    Time: $($sw.Elapsed.ToString('hh\:mm\:ss\.fff'))" -ForegroundColor Gray
    }
    
    $avg = ($times | Measure-Object -Property TotalMilliseconds -Average).Average
    $min = ($times | Measure-Object -Property TotalMilliseconds -Minimum).Minimum
    $max = ($times | Measure-Object -Property TotalMilliseconds -Maximum).Maximum
    
    Write-Host "`n[BENCHMARK] Results ($iterations iterations):" -ForegroundColor Green
    Write-Host "  Average: $([math]::Round($avg, 1)) ms" -ForegroundColor White
    Write-Host "  Min:     $([math]::Round($min, 1)) ms" -ForegroundColor White
    Write-Host "  Max:     $([math]::Round($max, 1)) ms" -ForegroundColor White
}

# ═══════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════

function Show-BuildSummary {
    $duration = (Get-Date) - $BuildState.StartTime
    
    Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  BUILD SUMMARY" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Total Files:    $($BuildState.TotalFiles)" -ForegroundColor White
    Write-Host "  Built:          $($BuildState.BuiltFiles)" -ForegroundColor Green
    Write-Host "  Failed:         $($BuildState.FailedFiles)" -ForegroundColor $(if ($BuildState.FailedFiles -eq 0) { "Green" } else { "Red" })
    Write-Host "  Skipped:        $($BuildState.SkippedFiles)" -ForegroundColor Gray
    Write-Host "  Warnings:       $($BuildState.Warnings.Count)" -ForegroundColor Yellow
    Write-Host "  Duration:       $($duration.ToString('hh\:mm\:ss\.fff'))" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    if ($BuildState.Errors.Count -gt 0) {
        Write-Host "`n  ERRORS:" -ForegroundColor Red
        foreach ($error in $BuildState.Errors) {
            Write-Host "    - $($error.File): $($error.Message)" -ForegroundColor Red
        }
    }
    
    if ($BuildState.Warnings.Count -gt 0) {
        Write-Host "`n  WARNINGS:" -ForegroundColor Yellow
        foreach ($warning in $BuildState.Warnings | Select-Object -First 5) {
            Write-Host "    - $($warning.File)" -ForegroundColor Yellow
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════
# Main Execution
# ═══════════════════════════════════════════════════════════════════════════

Initialize-BuildEnvironment

if ($Benchmark) {
    Start-BuildBenchmark
}
else {
    $files = Get-AssemblyFiles
    $filesToBuild = $files | Where-Object { Test-NeedsRebuild -SourceFile $_ }
    $BuildState.SkippedFiles = $files.Count - $filesToBuild.Count
    
    Write-Host "[BUILD] Files to build: $($filesToBuild.Count) (skipped: $($BuildState.SkippedFiles))" -ForegroundColor Cyan
    
    if ($filesToBuild.Count -gt 0) {
        if ($Parallel) {
            Start-ParallelBuild -Files $filesToBuild
        }
        else {
            Start-SerialBuild -Files $filesToBuild
        }
        
        Invoke-HotpatchGeneration
        Start-Linking
    }
    else {
        Write-Host "[BUILD] Nothing to build (all up to date)" -ForegroundColor Green
    }
    
    Show-BuildSummary
}

exit $(if ($BuildState.FailedFiles -eq 0) { 0 } else { 1 })
