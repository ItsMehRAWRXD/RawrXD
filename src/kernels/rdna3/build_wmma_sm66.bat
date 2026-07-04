@echo off
REM build_wmma_sm66.bat
REM Build script for RDNA3 WMMA via D3D12 SM 6.6
REM Target: RX 7800 XT (gfx1101)

echo ========================================
echo RDNA3 WMMA Build Script
echo Target: RX 7800 XT (gfx1101)
echo ========================================
echo.

set DXC_PATH=C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\dxc.exe
set VS_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717

if not exist "%DXC_PATH%" (
    echo ERROR: DXC not found at %DXC_PATH%
    echo Please install Windows SDK or adjust path
    exit /b 1
)

echo [1/3] Compiling HLSL shader...
"%DXC_PATH%" -T cs_6_6 -E main -Fo wmma_sm66.cso wmma_sm66.hlsl
if %ERRORLEVEL% neq 0 (
    echo ERROR: Shader compilation failed
    exit /b 1
)
echo      OK: wmma_sm66.cso created
echo.

echo [2/3] Compiling host application...
"%VS_PATH%\bin\Hostx64\x64\cl.exe" /O2 /W4 /EHsc /nologo /Fehost_wmma_sm66.exe host_wmma_sm66.cpp /link d3d12.lib dxgi.lib kernel32.lib user32.lib
if %ERRORLEVEL% neq 0 (
    echo ERROR: Host compilation failed
    exit /b 1
)
echo      OK: host_wmma_sm66.exe created
echo.

echo [3/3] Copying to build directory...
if not exist ..\..\..\build mkdir ..\..\..\build
copy /Y wmma_sm66.cso ..\..\..\build\
copy /Y host_wmma_sm66.exe ..\..\..\build\
echo      OK: Files copied to build directory
echo.

echo ========================================
echo Build Complete!
echo.
echo To run: cd ..\..\..\build ^&^& host_wmma_sm66.exe
echo ========================================
