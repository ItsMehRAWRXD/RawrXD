# Build and run multi-arch test
$ErrorActionPreference = "Stop"

$msvcRoot = "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231"
$sdkRoot = "C:\Program Files (x86)\Windows Kits\10"
$sdkVer = "10.0.22621.0"

# Set environment
$env:INCLUDE = "$msvcRoot\include;$sdkRoot\Include\$sdkVer\ucrt;$sdkRoot\Include\$sdkVer\shared;$sdkRoot\Include\$sdkVer\um"
$env:LIB = "$msvcRoot\lib\x64;$sdkRoot\Lib\$sdkVer\ucrt\x64;$sdkRoot\Lib\$sdkVer\um\x64"
$env:PATH = "$msvcRoot\bin\Hostx64\x64;$env:PATH"

$cl = "$msvcRoot\bin\Hostx64\x64\cl.exe"
$link = "$msvcRoot\bin\Hostx64\x64\link.exe"

Write-Host "Building multi-arch test..." -ForegroundColor Green

# Create output directory
New-Item -ItemType Directory -Force -Path "d:\rawrxd\build-ninja" | Out-Null

# Compile C++ files
Write-Host "Compiling test_multi_arch.cpp..."
& $cl /c /EHsc /O2 /I"d:\rawrxd\include" /I"d:\rawrxd\src\reverse_engineering" /I"d:\rawrxd\src\asm" /Fo"d:\rawrxd\build-ninja\test_multi_arch.obj" "d:\rawrxd\src\reverse_engineering\test_multi_arch.cpp"

Write-Host "Compiling RawrCodex_Multi.cpp..."
& $cl /c /EHsc /O2 /I"d:\rawrxd\include" /I"d:\rawrxd\src\reverse_engineering" /I"d:\rawrxd\src\asm" /Fo"d:\rawrxd\build-ninja\RawrCodex_Multi.obj" "d:\rawrxd\src\reverse_engineering\RawrCodex_Multi.cpp"

# Link
Write-Host "Linking..."
& $link /OUT:"d:\rawrxd\build-ninja\test_multi_arch.exe" "d:\rawrxd\build-ninja\test_multi_arch.obj" "d:\rawrxd\build-ninja\RawrCodex_Multi.obj" "d:\rawrxd\src\asm\RawrCodex.obj" kernel32.lib

Write-Host "Build complete!" -ForegroundColor Green

# Run the test
Write-Host "`nRunning test..." -ForegroundColor Cyan
& "d:\rawrxd\build-ninja\test_multi_arch.exe"
