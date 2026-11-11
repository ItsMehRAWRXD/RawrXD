# Silent Executable Debugger - PowerShell Version
# Analyzes and fixes silent compiler executables

param(
    [string]$CompilerDir = "D:\rawrxd\compilers",
    [string]$OutputDir = "D:\rawrxd\compilers\debug_logs"
)

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Find VS tools
$VSTools = $null
$PossiblePaths = @(
    "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36230\bin\Hostx64\x64",
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.51.36230\bin\Hostx64\x64",
    "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64",
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.51.36230\bin\Hostx64\x64"
)

foreach ($Path in $PossiblePaths) {
    if (Test-Path "$Path\dumpbin.exe") {
        $VSTools = $Path
        break
    }
}

if (-not $VSTools) {
    Write-Host "ERROR: VS Tools not found. Searching..." -ForegroundColor Red
    # Try to find anywhere
    $FoundDumpbin = Get-ChildItem -Path "C:\Program Files" -Recurse -Filter "dumpbin.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($FoundDumpbin) {
        $VSTools = Split-Path $FoundDumpbin.FullName
        Write-Host "Found at: $VSTools" -ForegroundColor Green
    } else {
        Write-Host "ERROR: dumpbin.exe not found. Cannot analyze executables." -ForegroundColor Red
        exit 1
    }
}

$Dumpbin = Join-Path $VSTools "dumpbin.exe"
$Link = Join-Path $VSTools "link.exe"
$Ml64 = Join-Path $VSTools "ml64.exe"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Silent Executable Debugger" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Tools:"
Write-Host "  DUMPBIN: $Dumpbin"
Write-Host "  LINK: $Link"
Write-Host "  ML64: $Ml64"
Write-Host "  Output: $OutputDir"
Write-Host ""

# List of executables to analyze
$Executables = @(
    "eon_bootstrap_compiler.exe",
    "bash_compiler_from_scratch.exe",
    "powershell_compiler_from_scratch.exe",
    "universal_compiler_runtime.exe",
    "universal_cross_platform_compiler.exe",
    "omega_pro_v3.exe",
    "omega_pro.exe",
    "OmegaPro_v3_fixed.exe"
)

function Analyze-Executable {
    param([string]$ExeName)
    
    $ExePath = Join-Path $CompilerDir $ExeName
    
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Yellow
    Write-Host "Analyzing: $ExeName" -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Yellow
    
    if (-not (Test-Path $ExePath)) {
        Write-Host "[SKIP] $ExeName not found" -ForegroundColor Gray
        return
    }
    
    $FileInfo = Get-Item $ExePath
    Write-Host "[INFO] File exists: $ExePath"
    Write-Host "[INFO] Size: $($FileInfo.Length) bytes"
    Write-Host "[INFO] Modified: $($FileInfo.LastWriteTime)"
    
    # Read PE header manually
    Write-Host ""
    Write-Host "--- Reading PE Header ---" -ForegroundColor Cyan
    
    try {
        $Bytes = [System.IO.File]::ReadAllBytes($ExePath)
        
        # Check MZ signature
        if ($Bytes[0] -eq 0x4D -and $Bytes[1] -eq 0x5A) {
            Write-Host "[OK] MZ signature valid (DOS header)"
            
            # Get PE offset
            $PEOffset = [BitConverter]::ToInt32($Bytes, 0x3C)
            Write-Host "[INFO] PE Header offset: 0x$($PEOffset.ToString('X8'))"
            
            # Check PE signature
            if ($Bytes[$PEOffset] -eq 0x50 -and $Bytes[$PEOffset + 1] -eq 0x45) {
                Write-Host "[OK] PE signature valid"
                
                # Get subsystem (offset from PE header: + optional header + subsystem offset)
                # COFF header is 24 bytes, subsystem is at offset 68 in optional header
                $SubsystemOffset = $PEOffset + 24 + 68
                if ($SubsystemOffset -lt $Bytes.Length) {
                    $Subsystem = [BitConverter]::ToUInt16($Bytes, $SubsystemOffset)
                    switch ($Subsystem) {
                        1 { Write-Host "[INFO] Subsystem: 1 (NATIVE)" }
                        2 { Write-Host "[INFO] Subsystem: 2 (WINDOWS_GUI) - REQUIRES FIX" -ForegroundColor Red }
                        3 { Write-Host "[INFO] Subsystem: 3 (WINDOWS_CUI) - Console application" -ForegroundColor Green }
                        5 { Write-Host "[INFO] Subsystem: 5 (OS2_CUI)" }
                        7 { Write-Host "[INFO] Subsystem: 7 (POSIX_CUI)" }
                        9 { Write-Host "[INFO] Subsystem: 9 (WINDOWS_CE_GUI)" }
                        10 { Write-Host "[INFO] Subsystem: 10 (EFI_APPLICATION)" }
                        12 { Write-Host "[INFO] Subsystem: 12 (EFI_BOOT_SERVICE_DRIVER)" }
                        default { Write-Host "[INFO] Subsystem: $Subsystem (Unknown)" }
                    }
                }
                
                # Get entry point
                $EntryPointOffset = $PEOffset + 24 + 16
                if ($EntryPointOffset -lt $Bytes.Length) {
                    $EntryPoint = [BitConverter]::ToUInt32($Bytes, $EntryPointOffset)
                    Write-Host "[INFO] Entry Point RVA: 0x$($EntryPoint.ToString('X8'))"
                }
                
                # Get machine type
                $MachineOffset = $PEOffset + 4
                $Machine = [BitConverter]::ToUInt16($Bytes, $MachineOffset)
                switch ($Machine) {
                    0x014C { Write-Host "[INFO] Machine: x86 (32-bit)" }
                    0x8664 { Write-Host "[INFO] Machine: x64 (64-bit)" }
                    default { Write-Host "[INFO] Machine: 0x$($Machine.ToString('X4'))" }
                }
            } else {
                Write-Host "[ERROR] Invalid PE signature" -ForegroundColor Red
            }
        } else {
            Write-Host "[ERROR] Invalid MZ signature" -ForegroundColor Red
        }
    } catch {
        Write-Host "[ERROR] Failed to read PE header: $_" -ForegroundColor Red
    }
    
    # Try dumpbin if available
    if (Test-Path $Dumpbin) {
        Write-Host ""
        Write-Host "--- Dumpbin Analysis ---" -ForegroundColor Cyan
        
        $HeaderLog = Join-Path $OutputDir "$ExeName`_headers.txt"
        & $Dumpbin /headers $ExePath 2>&1 | Out-File $HeaderLog
        
        if (Test-Path $HeaderLog) {
            $Headers = Get-Content $HeaderLog
            $SubsystemLine = $Headers | Select-String "subsystem"
            if ($SubsystemLine) {
                Write-Host "[DUMPBIN] $SubsystemLine"
            }
            
            $EntryLine = $Headers | Select-String "entry point"
            if ($EntryLine) {
                Write-Host "[DUMPBIN] $EntryLine"
            }
        }
    }
    
    # Test execution
    Write-Host ""
    Write-Host "--- Testing Execution ---" -ForegroundColor Cyan
    
    # Test 1: No arguments
    $Test1Log = Join-Path $OutputDir "$ExeName`_test1.txt"
    $StartTime = Get-Date
    try {
        $Process = Start-Process -FilePath $ExePath -RedirectStandardOutput $Test1Log `
            -RedirectStandardError "$Test1Log.err" -WindowStyle Hidden -PassThru -Wait
        $ExitCode = $Process.ExitCode
    } catch {
        "ERROR: $_" | Out-File $Test1Log
        $ExitCode = -1
    }
    $EndTime = Get-Date
    
    "Start: $StartTime" | Out-File $Test1Log -Append
    "Exit Code: $ExitCode" | Out-File $Test1Log -Append
    "End: $EndTime" | Out-File $Test1Log -Append
    
    if (Test-Path $Test1Log) {
        $Content = Get-Content $Test1Log -Raw
        if ($Content.Length -gt 50) {
            Write-Host "[RESULT] Produced output ($($Content.Length) bytes)" -ForegroundColor Green
        } else {
            Write-Host "[RESULT] No output (exit code: $ExitCode)" -ForegroundColor Yellow
        }
    }
    
    # Test 2: With --help
    $Test2Log = Join-Path $OutputDir "$ExeName`_test2.txt"
    try {
        $Process = Start-Process -FilePath $ExePath -ArgumentList "--help" `
            -RedirectStandardOutput $Test2Log -RedirectStandardError "$Test2Log.err" `
            -WindowStyle Hidden -PassThru -Wait
    } catch {}
    
    if (Test-Path $Test2Log) {
        $Content = Get-Content $Test2Log -Raw
        if ($Content.Length -gt 0) {
            Write-Host "[RESULT --help] Produced output ($($Content.Length) bytes)" -ForegroundColor Green
        } else {
            Write-Host "[RESULT --help] No output" -ForegroundColor Yellow
        }
    }
    
    # Test 3: With /?
    $Test3Log = Join-Path $OutputDir "$ExeName`_test3.txt"
    try {
        $Process = Start-Process -FilePath $ExePath -ArgumentList "/?" `
            -RedirectStandardOutput $Test3Log -RedirectStandardError "$Test3Log.err" `
            -WindowStyle Hidden -PassThru -Wait
    } catch {}
    
    if (Test-Path $Test3Log) {
        $Content = Get-Content $Test3Log -Raw
        if ($Content.Length -gt 0) {
            Write-Host "[RESULT /?] Produced output ($($Content.Length) bytes)" -ForegroundColor Green
        } else {
            Write-Host "[RESULT /?] No output" -ForegroundColor Yellow
        }
    }
    
    Write-Host ""
    Write-Host "--- Analysis Complete ---" -ForegroundColor Green
    Write-Host "Logs saved to: $OutputDir"
}

# Analyze all executables
foreach ($Exe in $Executables) {
    Analyze-Executable -ExeName $Exe
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Analysis Complete" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Review logs in: $OutputDir"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Check subsystem - if WINDOWS_GUI (2), needs to be converted to CONSOLE"
Write-Host "  2. Check entry point - should be mainCRTStartup for console apps"
Write-Host "  3. Check if executables need input files"
Write-Host ""
