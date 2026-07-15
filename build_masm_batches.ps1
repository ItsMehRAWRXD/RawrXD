# RawrXD MASM64 Batch Build System
# Production sources only - no archived orphans, no test artifacts
# Reverse order compilation (last file first) in batches of 15

$ML64 = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
$LINK = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
$OBJ_DIR = "d:\rawrxd\build\obj"
$BIN_DIR = "d:\rawrxd\build\bin"
$LOG_DIR = "d:\rawrxd\build\logs"

# Create directories
New-Item -ItemType Directory -Force -Path $OBJ_DIR | Out-Null
New-Item -ItemType Directory -Force -Path $BIN_DIR | Out-Null
New-Item -ItemType Directory -Force -Path $LOG_DIR | Out-Null

# Production source directories (priority order - core first)
$SourcePatterns = @(
    "d:\rawrxd\src\*.asm",
    "d:\rawrxd\src\asm\*.asm", 
    "d:\rawrxd\src\kernels\*.asm",
    "d:\rawrxd\src\masm\*.asm",
    "d:\rawrxd\src\masm\interconnect\*.asm",
    "d:\rawrxd\src\ui\*.asm",
    "d:\rawrxd\src\win32app\*.asm",
    "d:\rawrxd\src\thermal\masm\*.asm",
    "d:\rawrxd\src\thermal\agent_bridge\*.asm",
    "d:\rawrxd\src\thermal\agent_clients\*.asm",
    "d:\rawrxd\src\reverse_engineering\reverser_compiler\*.asm",
    "d:\rawrxd\src\reverse_engineering\omega_suite\v7\*.asm",
    "d:\rawrxd\src\reverse_engineering\deobfuscator\*.asm",
    "d:\rawrxd\src\pe_writer_production\*.asm",
    "d:\rawrxd\src\orchestrator\*.asm",
    "d:\rawrxd\src\gpu_masm\*.asm",
    "d:\rawrxd\src\gpu_masm\vulkan\*.asm",
    "d:\rawrxd\asm\*.asm",
    "d:\rawrxd\asm-sources\*.asm",
    "d:\rawrxd\backend\*.asm",
    "d:\rawrxd\tools\*.asm",
    "d:\rawrxd\UEC-X\core\masm64\*.asm"
)

# Collect all source files
$AllFiles = @()
foreach ($pattern in $SourcePatterns) {
    if (Test-Path $pattern) {
        $files = Get-ChildItem -Path $pattern -File | Where-Object { 
            $_.FullName -notmatch '\.archived_orphans' -and 
            $_.FullName -notmatch 'test_output_' -and
            $_.FullName -notmatch 'extracted_chats'
        }
        $AllFiles += $files
    }
}

# Remove duplicates and sort
$UniqueFiles = $AllFiles | Sort-Object FullName -Unique
$TotalFiles = $UniqueFiles.Count

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD MASM64 Production Build" -ForegroundColor Cyan
Write-Host "Total Source Files: $TotalFiles" -ForegroundColor Yellow
Write-Host "Batch Size: 15 files" -ForegroundColor Yellow
Write-Host "Compilation Order: REVERSE (last first)" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan

# Reverse the list (last file first)
$ReversedFiles = $UniqueFiles | Sort-Object FullName -Descending

# Calculate batches
$Batches = [math]::Ceiling($TotalFiles / 15)
Write-Host "Total Batches: $Batches" -ForegroundColor Green

$BatchResults = @()
$CurrentBatch = 1
$FileIndex = 0

foreach ($file in $ReversedFiles) {
    $BatchNum = [int]([math]::Floor($FileIndex / 15)) + 1
    $FileInBatch = ($FileIndex % 15) + 1
    
    $objName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name) + ".obj"
    $objPath = Join-Path $OBJ_DIR $objName
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
    $logFileName = "batch{0:D3}_{1}.log" -f $BatchNum,$baseName
    $logFile = Join-Path $LOG_DIR $logFileName
    
    Write-Host "[$BatchNum/$Batches] ($FileInBatch/15) Compiling: $($file.Name)" -NoNewline
    
    # Compile with ml64
    $proc = Start-Process -FilePath $ML64 -ArgumentList "/c", "/W3", "/nologo", "/Zi", "/Fo`"$objPath`"", "`"$($file.FullName)`"" -Wait -PassThru -RedirectStandardOutput $logFile -RedirectStandardError "$logFile.err"
    
    if ($proc.ExitCode -eq 0) {
        Write-Host " [OK]" -ForegroundColor Green
        $BatchResults += [PSCustomObject]@{
            Batch = $BatchNum
            File = $file.Name
            Status = "SUCCESS"
            ObjPath = $objPath
        }
    } else {
        Write-Host " [FAIL]" -ForegroundColor Red
        $BatchResults += [PSCustomObject]@{
            Batch = $BatchNum
            File = $file.Name
            Status = "FAILED"
            ObjPath = $null
        }
        # Stop on first failure in strict mode
        Write-Host "`nBUILD HALTED - Fix errors before continuing" -ForegroundColor Red
        break
    }
    
    $FileIndex++
}

# Summary
$SuccessCount = ($BatchResults | Where-Object { $_.Status -eq "SUCCESS" }).Count
$FailCount = ($BatchResults | Where-Object { $_.Status -eq "FAILED" }).Count

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "BUILD SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Files Processed: $($BatchResults.Count)" -ForegroundColor White
Write-Host "Successful: $SuccessCount" -ForegroundColor Green
Write-Host "Failed: $FailCount" -ForegroundColor Red

if ($FailCount -eq 0 -and $SuccessCount -gt 0) {
    Write-Host "`nAll files compiled successfully!" -ForegroundColor Green
    Write-Host "Objects in: $OBJ_DIR" -ForegroundColor Yellow
    
    # List all object files for linking
    $objFiles = Get-ChildItem -Path "$OBJ_DIR\*.obj" | Select-Object -ExpandProperty FullName
    Write-Host "`nObject files ready for linking: $($objFiles.Count)" -ForegroundColor Cyan
}
