# RawrXD Stale Build Blocker
# Prevents running old/stale builds that waste time with outdated behavior.
#
# Usage:
#   powershell -File tools/stale_build_blocker.ps1 -Exe <path> -SourceRoot <path>
#   powershell -File tools/stale_build_blocker.ps1  (defaults to build_w1)
#
# Exit codes:
#   0 = FRESH (exe is newer than all sources, safe to run)
#   1 = STALE (source files modified after exe, rebuild required)
#   2 = EXE_NOT_FOUND
#   3 = SOURCE_ROOT_NOT_FOUND

param(
    [string]$Exe = "F:\~dev\rawrxd\build_w1\bin\Release\RawrXD-Win32IDE.exe",
    [string]$RawrExe = "F:\~dev\rawrxd\build_w1\bin\Release\rawr.exe",
    [string]$SourceRoot = "F:\~dev\rawrxd\src",
    [string]$CMakeFile = "F:\~dev\rawrxd\CMakeLists.txt",
    [switch]$Block  # If set, exit 1 on stale (for pipeline use)
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Exe)) {
    Write-Output "STALE_BLOCKER=EXE_NOT_FOUND"
    Write-Output "EXE_PATH=$Exe"
    exit 2
}

if (-not (Test-Path $SourceRoot)) {
    Write-Output "STALE_BLOCKER=SOURCE_ROOT_NOT_FOUND"
    Write-Output "SOURCE_ROOT=$SourceRoot"
    exit 3
}

$exeTime = (Get-Item $Exe).LastWriteTime
$staleFiles = @()
$maxSourceTime = [datetime]::MinValue

# Check CMakeLists.txt
if (Test-Path $CMakeFile) {
    $cmakeTime = (Get-Item $CMakeFile).LastWriteTime
    if ($cmakeTime -gt $exeTime) {
        $staleFiles += "CMakeLists.txt ($($cmakeTime.ToString('HH:mm:ss')) > exe $($exeTime.ToString('HH:mm:ss')))"
    }
    if ($cmakeTime -gt $maxSourceTime) { $maxSourceTime = $cmakeTime }
}

# Check all .cpp, .h, .hpp, .asm files in source tree
$sourceExts = @('*.cpp', '*.h', '*.hpp', '*.asm', '*.c', '*.cxx', '*.cc', '*.inl')
foreach ($ext in $sourceExts) {
    $files = Get-ChildItem -Path $SourceRoot -Filter $ext -Recurse -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        if ($f.LastWriteTime -gt $exeTime) {
            $relPath = $f.FullName.Replace($SourceRoot, "")
            $staleFiles += "$relPath ($($f.LastWriteTime.ToString('HH:mm:ss')) > exe $($exeTime.ToString('HH:mm:ss')))"
        }
        if ($f.LastWriteTime -gt $maxSourceTime) { $maxSourceTime = $f.LastWriteTime }
    }
}

# Check rawr.exe too if it exists
$rawrStale = $false
if (Test-Path $RawrExe) {
    $rawrTime = (Get-Item $RawrExe).LastWriteTime
    if ($rawrTime -lt $exeTime) {
        # rawr.exe older than IDE — might be stale relative to its own sources
        # Check if rawr sources are newer than rawr.exe
        $rawrSources = @(
            "F:\~dev\rawrxd\src\deep2\rawr_run.cpp",
            "F:\~dev\rawrxd\src\deep2\rawrxd_run_modelname_001.cpp"
        )
        foreach ($src in $rawrSources) {
            if ((Test-Path $src) -and ((Get-Item $src).LastWriteTime -gt $rawrTime)) {
                $rawrStale = $true
                $staleFiles += "$(Split-Path $src -Leaf) ($((Get-Item $src).LastWriteTime.ToString('HH:mm:ss')) > rawr.exe $($rawrTime.ToString('HH:mm:ss')))"
            }
        }
    }
}

# Write receipt
$receiptPath = "F:\~dev\_stale_blocker_receipt.txt"
$verdict = if ($staleFiles.Count -eq 0) { "FRESH" } else { "STALE" }

@"
GATE=RAWRXD_STALE_BUILD_BLOCKER_001
DATE=$(Get-Date -Format 'yyyy-MM-dd')
EXE_PATH=$Exe
EXE_MODIFIED=$($exeTime.ToString('yyyy-MM-dd HH:mm:ss'))
SOURCE_ROOT=$SourceRoot
MAX_SOURCE_MODIFIED=$($maxSourceTime.ToString('yyyy-MM-dd HH:mm:ss'))
STALE_FILE_COUNT=$($staleFiles.Count)
VERDICT=$verdict
"@ | Set-Content $receiptPath -Encoding UTF8

if ($staleFiles.Count -eq 0) {
    Write-Output "STALE_BLOCKER=FRESH"
    Write-Output "EXE_MODIFIED=$($exeTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Output "MAX_SOURCE_MODIFIED=$($maxSourceTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Output "VERDICT=FRESH"
    Write-Output "Safe to run."
    exit 0
} else {
    Write-Output "STALE_BLOCKER=STALE"
    Write-Output "EXE_MODIFIED=$($exeTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Output "MAX_SOURCE_MODIFIED=$($maxSourceTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Output "STALE_FILE_COUNT=$($staleFiles.Count)"
    Write-Output ""
    Write-Output "=== Stale files (source newer than exe) ==="
    foreach ($f in $staleFiles | Select-Object -First 20) {
        Write-Output "  $f"
    }
    if ($staleFiles.Count -gt 20) {
        Write-Output "  ... and $($staleFiles.Count - 20) more"
    }
    Write-Output ""
    Write-Output "REBUILD REQUIRED:"
    Write-Output "  cmake --build F:\~dev\rawrxd\build_w1 --config Release --target RawrXD-Win32IDE -j 2"
    Write-Output "  cmake --build F:\~dev\rawrxd\build_w1 --config Release --target rawr -j 2"
    Write-Output "VERDICT=STALE"
    
    if ($Block) {
        exit 1
    } else {
        Write-Output ""
        Write-Output "(Use -Block to force exit 1 for pipeline use)"
        exit 1
    }
}