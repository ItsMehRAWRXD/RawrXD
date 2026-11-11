# Rebuild and run SiLU test

$VS_PATH = "C:\Program Files\Microsoft Visual Studio\18\Enterprise"
$MSVC_VER = (Get-ChildItem "$VS_PATH\VC\Tools\MSVC" | Sort-Object Name -Descending | Select-Object -First 1).Name
$CL = "$VS_PATH\VC\Tools\MSVC\$MSVC_VER\bin\Hostx64\x64\cl.exe"

$SDK_PATH = "C:\Program Files (x86)\Windows Kits\10"
$SDK_VER = "10.0.22621.0"

$env:INCLUDE = "$VS_PATH\VC\Tools\MSVC\$MSVC_VER\include;$SDK_PATH\Include\$SDK_VER\ucrt;$SDK_PATH\Include\$SDK_VER\shared;$SDK_PATH\Include\$SDK_VER\um"
$env:LIB = "$VS_PATH\VC\Tools\MSVC\$MSVC_VER\lib\x64;$SDK_PATH\Lib\$SDK_VER\ucrt\x64;$SDK_PATH\Lib\$SDK_VER\um\x64"

cd d:\rawrxd-ci-bootstrap\tests\kernels

Write-Host "Building SiLU test..."
& $CL /std:c11 /EHsc /O2 /Fe:test_silu_activation.exe test_silu_activation.c

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build successful! Running test..."
    .\test_silu_activation.exe
} else {
    Write-Host "Build failed!"
}
