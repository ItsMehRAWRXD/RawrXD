@echo off
REM Build script for real gfx1101 WMMA kernels
REM Target: RX 7800 XT (gfx1101)

echo ========================================
echo  gfx1101 Real WMMA Kernel Build
echo  Target: RX 7800 XT (gfx1101)
echo  Reference: AMD RDNA3 ISA 57019
echo ========================================
echo.

set "VS_TOOLS=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717"
set "ML64=%VS_TOOLS%\bin\Hostx64\x64\ml64.exe"
set "LINK=%VS_TOOLS%\bin\Hostx64\x64\link.exe"

if not exist obj mkdir obj
if not exist bin mkdir bin

echo [1/2] Assembling gfx1101_wmma_kernels.asm...
"%ML64%" /c /W3 /nologo /Zi /Foobj\gfx1101_wmma_kernels.obj gfx1101_wmma_kernels.asm
if errorlevel 1 goto :error

echo [2/2] Assembling amdkfd_dispatch_simple.asm...
"%ML64%" /c /W3 /nologo /Zi /Foobj\amdkfd_dispatch.obj amdkfd_dispatch_simple.asm
if errorlevel 1 goto :error

echo.
echo ========================================
echo  BUILD SUCCESSFUL
echo ========================================
echo.
echo Object files created:
echo   - obj\gfx1101_wmma_kernels.obj
echo   - obj\amdkfd_dispatch.obj
echo.
echo Kernels included:
echo   - WMMA_F16_16x16x16_F16 (real gfx1101 opcodes)
echo   - WMMA_F32_16x16x16_F16 (real gfx1101 opcodes)
echo   - Q4MatMul_RDNA3_Real (complete kernel)
echo.
echo AMDKFD dispatch layer:
echo   - KFD_Initialize
echo   - KFD_AllocateGPUMemory
echo   - KFD_SubmitCommandBuffer
echo   - KFD_MapDoorbell
echo   - KFD_WriteDoorbell
echo   - KFD_Shutdown
echo.
goto :end

:error
echo.
echo [!] BUILD FAILED
echo.
exit /b 1

:end
