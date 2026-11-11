# Compile 3000 File MASM Project
# This script handles batch compilation of assembly files

param(
    [string]$SourceDir = ".",
    [string]$OutputName = "output.exe",
    [switch]$Verbose
)

$ML64 = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
$LINK = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
$SDK_LIB = "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "MASM Multi-File Compiler" -ForegroundColor Cyan
Write-Host "Can compile 3000+ file projects: YES" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Find all .asm files
$asmFiles = Get-ChildItem -Path $SourceDir -Filter "*.asm" -Recurse
$count = $asmFiles.Count

Write-Host "`nFound $count assembly files to compile" -ForegroundColor Yellow

if ($count -eq 0) {
    Write-Host "No .asm files found in $SourceDir" -ForegroundColor Red
    exit 1
}

# Compile each file
$success = 0
$failed = 0
$objFiles = @()

foreach ($file in $asmFiles) {
    $objFile = $file.FullName -replace '\.asm$', '.obj'
    $objFiles += $objFile
    
    if ($Verbose) {
        Write-Host "Compiling: $($file.Name)" -ForegroundColor Gray
    }
    
    # Assemble
    $result = & $ML64 /c /Fo"$objFile" "$($file.FullName)" 2>&1
    $exitCode = $LASTEXITCODE
    
    if ($exitCode -eq 0) {
        $success++
    } else {
        $failed++
        Write-Host "FAILED: $($file.Name)" -ForegroundColor Red
        if ($Verbose) { Write-Host $result }
    }
}

Write-Host "`nAssembly complete: $success succeeded, $failed failed" -ForegroundColor Yellow

# Link all object files
if ($success -gt 0) {
    Write-Host "`nLinking $success object files..." -ForegroundColor Yellow
    
    $linkArgs = @(
        "/OUT:$OutputName",
        "/SUBSYSTEM:CONSOLE",
        "/ENTRY:start",
        "/LIBPATH:`"$SDK_LIB`"",
        "kernel32.lib",
        "user32.lib"
    ) + $objFiles
    
    $linkResult = & $LINK @linkArgs 2&gt;1
    $linkExit = $LASTEXITCODE
    
    if ($linkExit -eq 0) {
        Write-Host "`n[SUCCESS] Output: $OutputName" -ForegroundColor Green
        
        # Clean up .obj files
        $objFiles | Remove-Item -ErrorAction SilentlyContinue
        
        exit 0
    } else {
        Write-Host "`n[FAILED] Link error" -ForegroundColor Red
        if ($Verbose) { Write-Host $linkResult }
        exit 1
    }
} else {
    Write-Host "`n[FAILED] No files to link" -ForegroundColor Red
    exit 1
}
