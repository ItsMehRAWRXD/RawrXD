# Build Deep2 HTTP Server - PowerShell Script
# ===========================================

$vsPaths = @(
    "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
)

$vsPath = $null
foreach ($path in $vsPaths) {
    if (Test-Path $path) {
        $vsPath = $path
        break
    }
}

if (-not $vsPath) {
    Write-Error "Could not find vcvars64.bat"
    exit 1
}

Write-Host "Using VS path: $vsPath"

# Create batch file to run build
$batchContent = @"
@echo off
call "$vsPath"
cd /d "d:\rawrxd\src\deep2"
cl.exe /nologo /W4 /O2 /arch:AVX2 /EHsc /std:c++20 /I. /D_CRT_SECURE_NO_WARNINGS /Fe:Deep2Server_Minimal.exe Deep2Server_Minimal.cpp /link /SUBSYSTEM:CONSOLE ws2_32.lib
if %ERRORLEVEL% NEQ 0 (
    echo BUILD FAILED
    exit /b %ERRORLEVEL%
)
echo BUILD SUCCESS
"@

$batchPath = "d:\rawrxd\src\deep2\_build_temp.bat"
$batchContent | Out-File -FilePath $batchPath -Encoding ASCII

# Execute batch file
& cmd /c $batchPath

# Check result
if (Test-Path "d:\rawrxd\src\deep2\Deep2Server_Minimal.exe") {
    Write-Host "`n=========================================="
    Write-Host "BUILD SUCCESSFUL"
    Write-Host "Executable: Deep2Server_Minimal.exe"
    Write-Host "=========================================="
    
    # Get file info
    $exe = Get-Item "d:\rawrxd\src\deep2\Deep2Server_Minimal.exe"
    Write-Host "Size: $($exe.Length) bytes"
    Write-Host "Created: $($exe.LastWriteTime)"
} else {
    Write-Error "Build failed - executable not found"
}

# Cleanup
Remove-Item $batchPath -ErrorAction SilentlyContinue
