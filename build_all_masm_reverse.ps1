# RawrXD Mass MASM Build Script - Reverse Order Compilation
# Compiles all 841+ MASM x64 files in batches of 15, working backwards
# Then links into final RawrXD_x64_IDE.exe

param(
    [int]$BatchSize = 15,
    [int]$MaxParallelJobs = 8,
    [string]$BuildDir = "d:\rawrxd\build-masm-x64",
    [string]$SourceDir = "d:\rawrxd\src",
    [switch]$SkipCompile = $false,
    [switch]$LinkOnly = $false
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "Continue"

# Tool Paths
$ML64 = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
$LINK = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"

# Verify tools exist
if (-not (Test-Path $ML64)) {
    Write-Error "ml64.exe not found at: $ML64"
    exit 1
}
if (-not (Test-Path $LINK)) {
    Write-Error "link.exe not found at: $LINK"
    exit 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD Mass MASM x64 Build System" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ML64: $ML64" -ForegroundColor Gray
Write-Host "LINK: $LINK" -ForegroundColor Gray
Write-Host "Build Directory: $BuildDir" -ForegroundColor Gray
Write-Host "Source Directory: $SourceDir" -ForegroundColor Gray
Write-Host "Batch Size: $BatchSize" -ForegroundColor Gray
Write-Host "Max Parallel Jobs: $MaxParallelJobs" -ForegroundColor Gray
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Create build directory
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
New-Item -ItemType Directory -Force -Path "$BuildDir\obj" | Out-Null
New-Item -ItemType Directory -Force -Path "$BuildDir\logs" | Out-Null

$FailureLog = "$BuildDir\logs\build_failures.log"
$SuccessLog = "$BuildDir\logs\build_success.log"
$LinkLog = "$BuildDir\logs\link.log"

# Clear previous logs
"Build Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File -FilePath $FailureLog -Encoding UTF8
"Build Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File -FilePath $SuccessLog -Encoding UTF8

# Get all ASM files
if (-not $LinkOnly) {
    Write-Host "Scanning for MASM source files..." -ForegroundColor Yellow
    $asmFiles = Get-ChildItem -Path $SourceDir -Filter "*.asm" -Recurse | 
        Where-Object { 
            $_.FullName -notmatch "archive|backup|\.git|test.*\.asm$|_test\.asm$|_stub\.asm$" 
        } |
        Sort-Object FullName
    
    $totalFiles = $asmFiles.Count
    Write-Host "Found $totalFiles MASM files to compile" -ForegroundColor Green
    Write-Host ""
    
    if ($totalFiles -eq 0) {
        Write-Error "No ASM files found!"
        exit 1
    }
    
    # Reverse order compilation (catches stub dependencies early)
    $reversedFiles = $asmFiles | Sort-Object FullName -Descending
    
    # Process in batches
    $batchCount = [Math]::Ceiling($totalFiles / $BatchSize)
    $currentBatch = 0
    $successCount = 0
    $failCount = 0
    $jobs = @()
    
    Write-Host "Starting REVERSE ORDER compilation (Batch $BatchSize)..." -ForegroundColor Cyan
    Write-Host "Processing from file $totalFiles down to file 1" -ForegroundColor Cyan
    Write-Host ""
    
    for ($i = 0; $i -lt $totalFiles; $i += $BatchSize) {
        $currentBatch++
        $endIndex = [Math]::Min($i + $BatchSize - 1, $totalFiles - 1)
        $batchFiles = $reversedFiles[$i..$endIndex]
        
        $progressPercent = [Math]::Round(($i / $totalFiles) * 100, 1)
        Write-Progress -Activity "Compiling MASM Files (Reverse Order)" -Status "Batch $currentBatch of $batchCount ($progressPercent%)" -PercentComplete $progressPercent
        
        Write-Host "[$currentBatch/$batchCount] Processing batch of $($batchFiles.Count) files..." -ForegroundColor Yellow
        
        # Compile each file in batch with parallel jobs
        $batchJobs = @()
        foreach ($file in $batchFiles) {
            $objFile = "$BuildDir\obj\$($file.BaseName).obj"
            $logFile = "$BuildDir\logs\$($file.BaseName).log"
            
            # Skip if already compiled and source hasn't changed
            if (Test-Path $objFile) {
                $objTime = (Get-Item $objFile).LastWriteTime
                $srcTime = $file.LastWriteTime
                if ($objTime -gt $srcTime) {
                    Write-Host "  [SKIP] $($file.Name) (up to date)" -ForegroundColor DarkGray
                    $successCount++
                    continue
                }
            }
            
            $jobScript = {
                param($ML64, $sourceFile, $objFile, $logFile)
                $includes = "/I`"d:\rawrxd\include`" /I`"d:\rawrxd\src\include`" /I`"d:\rawrxd\src\asm`""
                $cmd = "& `"$ML64`" /c /W3 /nologo /Zi /Zd /Fo`"$objFile`" $includes `"$sourceFile`" 2>&1 | Out-File -FilePath `"$logFile`" -Encoding UTF8"
                Invoke-Expression $cmd
                return $LASTEXITCODE
            }
            
            $job = Start-Job -ScriptBlock $jobScript -ArgumentList $ML64, $file.FullName, $objFile, $logFile -Name $file.BaseName
            $batchJobs += $job
            $jobs += $job
            
            # Throttle parallel jobs
            while ((Get-Job -State Running).Count -ge $MaxParallelJobs) {
                Start-Sleep -Milliseconds 100
            }
        }
        
        # Wait for batch to complete
        if ($batchJobs.Count -gt 0) {
            $batchJobs | Wait-Job | Out-Null
            
            # Check results
            foreach ($job in $batchJobs) {
                $result = Receive-Job -Job $job
                $fileName = $job.Name
                $logFile = "$BuildDir\logs\$fileName.log"
                
                if ($result -eq 0 -and (Test-Path "$BuildDir\obj\$fileName.obj")) {
                    Write-Host "  [OK] $fileName" -ForegroundColor Green
                    "$fileName - SUCCESS" | Out-File -FilePath $SuccessLog -Append -Encoding UTF8
                    $successCount++
                } else {
                    Write-Host "  [FAIL] $fileName" -ForegroundColor Red
                    $logContent = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
                    "$fileName - FAILED" | Out-File -FilePath $FailureLog -Append -Encoding UTF8
                    $logContent | Out-File -FilePath $FailureLog -Append -Encoding UTF8
                    "---" | Out-File -FilePath $FailureLog -Append -Encoding UTF8
                    $failCount++
                }
                
                Remove-Job -Job $job
            }
        }
        
        Write-Host "  Batch $currentBatch complete: $successCount success, $failCount failed" -ForegroundColor Gray
        Write-Host ""
    }
    
    Write-Progress -Activity "Compiling MASM Files" -Completed
    
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Compilation Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Total Files: $totalFiles" -ForegroundColor White
    Write-Host "Successful: $successCount" -ForegroundColor Green
    Write-Host "Failed: $failCount" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($failCount -gt 0) {
        Write-Host "WARNING: $failCount files failed to compile!" -ForegroundColor Red
        Write-Host "Check $FailureLog for details" -ForegroundColor Yellow
        Write-Host ""
    }
}

# LINKING PHASE
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "LINKING PHASE: Building RawrXD_x64_IDE.exe" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Collect all object files
$objFiles = Get-ChildItem -Path "$BuildDir\obj" -Filter "*.obj" | Select-Object -ExpandProperty FullName

if ($objFiles.Count -eq 0) {
    Write-Error "No object files found to link!"
    exit 1
}

Write-Host "Linking $($objFiles.Count) object files..." -ForegroundColor Yellow

# Create response file for linker (avoids command line length limits)
$responseFile = "$BuildDir\link_response.txt"
$objFiles | Out-File -FilePath $responseFile -Encoding ASCII

# Link command
$linkArgs = @(
    "@$responseFile",
    "/OUT:`"$BuildDir\RawrXD_x64_IDE.exe`"",
    "/SUBSYSTEM:WINDOWS",
    "/ENTRY:WinMainCRTStartup",
    "/LARGEADDRESSAWARE",
    "/MACHINE:X64",
    "/DEBUG:FULL",
    "/OPT:REF",
    "/OPT:ICF",
    "kernel32.lib",
    "user32.lib",
    "gdi32.lib",
    "shell32.lib",
    "ole32.lib",
    "oleaut32.lib",
    "uuid.lib",
    "advapi32.lib",
    "ws2_32.lib",
    "winmm.lib",
    "comdlg32.lib",
    "comctl32.lib",
    "shlwapi.lib",
    "msimg32.lib",
    "version.lib",
    "imm32.lib",
    "dwmapi.lib",
    "uxtheme.lib",
    "/NODEFAULTLIB:libcmt.lib",
    "/NODEFAULTLIB:msvcrt.lib"
)

$linkCmd = "& `"$LINK`" $($linkArgs -join ' ') 2>&1 | Tee-Object -FilePath `"$LinkLog`" -Encoding UTF8"
Write-Host "Executing linker..." -ForegroundColor Yellow
Invoke-Expression $linkCmd
$linkResult = $LASTEXITCODE

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Link Result" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($linkResult -eq 0 -and (Test-Path "$BuildDir\RawrXD_x64_IDE.exe")) {
    $exeInfo = Get-Item "$BuildDir\RawrXD_x64_IDE.exe"
    Write-Host "SUCCESS: RawrXD_x64_IDE.exe built!" -ForegroundColor Green
    Write-Host "  Path: $($exeInfo.FullName)" -ForegroundColor Gray
    Write-Host "  Size: $([Math]::Round($exeInfo.Length / 1MB, 2)) MB" -ForegroundColor Gray
    Write-Host "  Objects Linked: $($objFiles.Count)" -ForegroundColor Gray
    Write-Host ""
    
    # Verify PE header
    Write-Host "Verifying PE executable..." -ForegroundColor Yellow
    $dumpbin = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\dumpbin.exe"
    if (Test-Path $dumpbin) {
        & $dumpbin /headers "$BuildDir\RawrXD_x64_IDE.exe" 2>&1 | Select-Object -First 30 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    }
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "BUILD COMPLETE!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  1. Smoke test: & '$BuildDir\RawrXD_x64_IDE.exe'" -ForegroundColor White
    Write-Host "  2. Check logs: $BuildDir\logs\" -ForegroundColor White
    Write-Host ""
    
    exit 0
} else {
    Write-Host "FAILED: Link step failed with code $linkResult" -ForegroundColor Red
    Write-Host "Check $LinkLog for details" -ForegroundColor Yellow
    Write-Host ""
    
    # Show last errors
    if (Test-Path $LinkLog) {
        Write-Host "Last 20 lines of link log:" -ForegroundColor Yellow
        Get-Content $LinkLog -Tail 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    }
    
    exit 1
}
