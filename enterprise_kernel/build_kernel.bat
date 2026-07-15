@echo off
REM ============================================================================
REM RAWRXD Enterprise Kernel Build Script
REM Pure MASM x64 - No CRT Dependencies
REM ============================================================================

setlocal EnableDelayedExpansion

echo.
echo ========================================
echo RAWRXD Enterprise Kernel Build System
echo ========================================
echo.

REM ============================================================================
REM Configuration
REM ============================================================================
set KERNEL_NAME=RAWRXD_Enterprise_Kernel
set BUILD_DIR=d:\rawrxd\enterprise_kernel
set OUTPUT_DIR=d:\rawrxd\enterprise_kernel\output
set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe

REM ============================================================================
REM Validate Tools
REM ============================================================================
if not exist "%ML64%" (
    echo ERROR: ml64.exe not found at: %ML64%
    exit /b 1
)

if not exist "%LINK%" (
    echo ERROR: link.exe not found at: %LINK%
    exit /b 1
)

echo [OK] Toolchain validated
echo.

REM ============================================================================
REM Create Output Directory
REM ============================================================================
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

REM ============================================================================
REM Assembly Phase
REM ============================================================================
echo [1/9] Assembling RAWRXD_MAIN.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%OUTPUT_DIR%\RAWRXD_MAIN.obj" "%BUILD_DIR%\RAWRXD_MAIN.asm"
if errorlevel 1 goto :asm_error

echo [2/9] Assembling RAWRXD_TELEMETRY.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%OUTPUT_DIR%\RAWRXD_TELEMETRY.obj" "%BUILD_DIR%\RAWRXD_TELEMETRY.asm"
if errorlevel 1 goto :asm_error

echo [3/9] Assembling RAWRXD_SMOKE.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%OUTPUT_DIR%\RAWRXD_SMOKE.obj" "%BUILD_DIR%\RAWRXD_SMOKE.asm"
if errorlevel 1 goto :asm_error

echo [4/9] Assembling RAWRXD_INTEGRATION.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%OUTPUT_DIR%\RAWRXD_INTEGRATION.obj" "%BUILD_DIR%\RAWRXD_INTEGRATION.asm"
if errorlevel 1 goto :asm_error

echo [5/9] Assembling RAWRXD_STRESS.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%OUTPUT_DIR%\RAWRXD_STRESS.obj" "%BUILD_DIR%\RAWRXD_STRESS.asm"
if errorlevel 1 goto :asm_error

echo [6/9] Assembling RAWRXD_SOAK.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%OUTPUT_DIR%\RAWRXD_SOAK.obj" "%BUILD_DIR%\RAWRXD_SOAK.asm"
if errorlevel 1 goto :asm_error

echo [7/9] Assembling RAWRXD_WSI.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%OUTPUT_DIR%\RAWRXD_WSI.obj" "%BUILD_DIR%\RAWRXD_WSI.asm"
if errorlevel 1 goto :asm_error

echo [8/9] Assembling RAWRXD_ESI.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%OUTPUT_DIR%\RAWRXD_ESI.obj" "%BUILD_DIR%\RAWRXD_ESI.asm"
if errorlevel 1 goto :asm_error

echo [9/9] Assembling RAWRXD_REGRESSION.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%OUTPUT_DIR%\RAWRXD_REGRESSION.obj" "%BUILD_DIR%\RAWRXD_REGRESSION.asm"
if errorlevel 1 goto :asm_error

echo [10/20] Assembling RAWRXD_CI_GATE.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%OUTPUT_DIR%\RAWRXD_CI_GATE.obj" "%BUILD_DIR%\RAWRXD_CI_GATE.asm"
if errorlevel 1 goto :asm_error

echo [11/20] Assembling RAWRXD_SELFHEAL.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%OUTPUT_DIR%\RAWRXD_SELFHEAL.obj" "%BUILD_DIR%\RAWRXD_SELFHEAL.asm"
if errorlevel 1 goto :asm_error

echo [12/20] Assembling RAWRXD_ARE.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%OUTPUT_DIR%\RAWRXD_ARE.obj" "%BUILD_DIR%\RAWRXD_ARE.asm"
if errorlevel 1 goto :asm_error

echo [13/20] Assembling RAWRXD_HOTPATCH.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%OUTPUT_DIR%\RAWRXD_HOTPATCH.obj" "%BUILD_DIR%\RAWRXD_HOTPATCH.asm"
if errorlevel 1 goto :asm_error

echo [14/20] Assembling RAWRXD_RCL.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%OUTPUT_DIR%\RAWRXD_RCL.obj" "%BUILD_DIR%\RAWRXD_RCL.asm"
if errorlevel 1 goto :asm_error

echo [15/20] Assembling RAWRXD_SEMK.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%OUTPUT_DIR%\RAWRXD_SEMK.obj" "%BUILD_DIR%\RAWRXD_SEMK.asm"
if errorlevel 1 goto :asm_error

echo [16/20] Assembling RAWRXD_AISM.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%OUTPUT_DIR%\RAWRXD_AISM.obj" "%BUILD_DIR%\RAWRXD_AISM.asm"
if errorlevel 1 goto :asm_error

echo [17/20] Assembling RAWRXD_UIBF.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%OUTPUT_DIR%\RAWRXD_UIBF.obj" "%BUILD_DIR%\RAWRXD_UIBF.asm"
if errorlevel 1 goto :asm_error

echo [18/20] Assembling RAWRXD_ZSIC.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%OUTPUT_DIR%\RAWRXD_ZSIC.obj" "%BUILD_DIR%\RAWRXD_ZSIC.asm"
if errorlevel 1 goto :asm_error

echo [19/20] Assembling RAWRXD_PLIM.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%OUTPUT_DIR%\RAWRXD_PLIM.obj" "%BUILD_DIR%\RAWRXD_PLIM.asm"
if errorlevel 1 goto :asm_error

echo [20/20] Assembling RAWRXD_FEPM.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%OUTPUT_DIR%\RAWRXD_FEPM.obj" "%BUILD_DIR%\RAWRXD_FEPM.asm"
if errorlevel 1 goto :asm_error

echo.
echo [OK] All assembly units compiled successfully
echo.

REM ============================================================================
REM Link Phase
REM ============================================================================
echo [LINK] Linking Enterprise Kernel...

"%LINK%" ^
    /SUBSYSTEM:CONSOLE ^
    /ENTRY:WinMain ^
    /NODEFAULTLIB ^
    /LARGEADDRESSAWARE:NO ^
    /OUT:"%OUTPUT_DIR%\%KERNEL_NAME%.exe" ^
    "%OUTPUT_DIR%\RAWRXD_MAIN.obj" ^
    "%OUTPUT_DIR%\RAWRXD_TELEMETRY.obj" ^
    "%OUTPUT_DIR%\RAWRXD_SMOKE.obj" ^
    "%OUTPUT_DIR%\RAWRXD_INTEGRATION.obj" ^
    "%OUTPUT_DIR%\RAWRXD_STRESS.obj" ^
    "%OUTPUT_DIR%\RAWRXD_SOAK.obj" ^
    "%OUTPUT_DIR%\RAWRXD_WSI.obj" ^
    "%OUTPUT_DIR%\RAWRXD_ESI.obj" ^
    "%OUTPUT_DIR%\RAWRXD_REGRESSION.obj" ^
    "%OUTPUT_DIR%\RAWRXD_CI_GATE.obj" ^
    "%OUTPUT_DIR%\RAWRXD_SELFHEAL.obj" ^
    "%OUTPUT_DIR%\RAWRXD_ARE.obj" ^
    "%OUTPUT_DIR%\RAWRXD_HOTPATCH.obj" ^
    "%OUTPUT_DIR%\RAWRXD_RCL.obj" ^
    "%OUTPUT_DIR%\RAWRXD_SEMK.obj" ^
    "%OUTPUT_DIR%\RAWRXD_AISM.obj" ^
    "%OUTPUT_DIR%\RAWRXD_UIBF.obj" ^
    "%OUTPUT_DIR%\RAWRXD_ZSIC.obj" ^
    "%OUTPUT_DIR%\RAWRXD_PLIM.obj" ^
    "%OUTPUT_DIR%\RAWRXD_FEPM.obj" ^
    "%OUTPUT_DIR%\RAWRXD_VIRS.obj" ^
    "%OUTPUT_DIR%\RAWRXD_CEBM.obj" ^
    "%OUTPUT_DIR%\RAWRXD_SSPE.obj" ^
    "%OUTPUT_DIR%\RAWRXD_AFP.obj" ^
    kernel32.lib

if errorlevel 1 goto :link_error

echo.
echo ========================================
echo BUILD SUCCESSFUL
echo ========================================
echo.
echo Output: %OUTPUT_DIR%\%KERNEL_NAME%.exe
echo.

REM ============================================================================
REM Verify Binary
REM ============================================================================
if exist "%OUTPUT_DIR%\%KERNEL_NAME%.exe" (
    echo [VERIFY] Binary created successfully
    for %%F in ("%OUTPUT_DIR%\%KERNEL_NAME%.exe") do (
        echo [VERIFY] Size: %%~zF bytes
    )
    echo.
    echo Run with: %OUTPUT_DIR%\%KERNEL_NAME%.exe
) else (
    echo [ERROR] Binary not found after linking
    exit /b 1
)

goto :end

:asm_error
echo.
echo ========================================
echo ASSEMBLY ERROR
echo ========================================
exit /b 1

:link_error
echo.
echo ========================================
echo LINK ERROR
echo ========================================
exit /b 1

:end
echo.
echo Build complete.
endlocal
