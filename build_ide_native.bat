@echo off
REM RawrXD IDE Build Script - Native Toolchain Only
REM No ML64.exe or LINK.exe required

echo ==========================================
echo  RawrXD IDE Build - Native Toolchain
echo ==========================================
echo.

set SRC_DIR=d:\rawrxd\src\asm
set OUT_DIR=d:\rawrxd\build-ide-native
set TOOLCHAIN=d:\rawrxd\compilers\native_toolchain

if not exist %OUT_DIR% mkdir %OUT_DIR%

echo [1/4] Assembling IDE Components...
echo.

REM Core IDE Components
"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\win32ide_main.asm" "%OUT_DIR%\win32ide_main.obj"
if errorlevel 1 goto :asm_error

echo   win32ide_main.asm - OK

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\RawrXD_IDE_Validator.asm" "%OUT_DIR%\RawrXD_IDE_Validator.obj"
if errorlevel 1 goto :asm_error

echo   RawrXD_IDE_Validator.asm - OK

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\RawrXD_RefProvider.asm" "%OUT_DIR%\RawrXD_RefProvider.obj"
if errorlevel 1 goto :asm_error

echo   RawrXD_RefProvider.asm - OK

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\RawrXD_Sidebar_x64.asm" "%OUT_DIR%\RawrXD_Sidebar_x64.obj"
if errorlevel 1 goto :asm_error

echo   RawrXD_Sidebar_x64.asm - OK

echo.
echo [2/4] Assembling Kernel Components...
echo.

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\RawrCodex.asm" "%OUT_DIR%\RawrCodex.obj"
if errorlevel 1 goto :asm_error

echo   RawrCodex.asm - OK

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\sovereign_kernels.asm" "%OUT_DIR%\sovereign_kernels.obj"
if errorlevel 1 goto :asm_error

echo   sovereign_kernels.asm - OK

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\FlashAttention_AVX512.asm" "%OUT_DIR%\FlashAttention_AVX512.obj"
if errorlevel 1 goto :asm_error

echo   FlashAttention_AVX512.asm - OK

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\dequant_simd.asm" "%OUT_DIR%\dequant_simd.obj"
if errorlevel 1 goto :asm_error

echo   dequant_simd.asm - OK

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\avx512_matmul.asm" "%OUT_DIR%\avx512_matmul.obj"
if errorlevel 1 goto :asm_error

echo   avx512_matmul.asm - OK

"%TOOLCHAIN%\rawrxd_native_assembler.exe" /c "%SRC_DIR%\RawrXD_Inference_AVX512.asm" "%OUT_DIR%\RawrXD_Inference_AVX512.obj"
if errorlevel 1 goto :asm_error

echo   RawrXD_Inference_AVX512.asm - OK

echo.
echo [3/4] Linking IDE Executable...
echo.

"%TOOLCHAIN%\rawrxd_native_linker.exe" ^
    "%OUT_DIR%\win32ide_main.obj" ^
    "%OUT_DIR%\RawrXD_IDE_Validator.obj" ^
    "%OUT_DIR%\RawrXD_RefProvider.obj" ^
    "%OUT_DIR%\RawrXD_Sidebar_x64.obj" ^
    "%OUT_DIR%\RawrCodex.obj" ^
    "%OUT_DIR%\sovereign_kernels.obj" ^
    "%OUT_DIR%\FlashAttention_AVX512.obj" ^
    "%OUT_DIR%\dequant_simd.obj" ^
    "%OUT_DIR%\avx512_matmul.obj" ^
    "%OUT_DIR%\RawrXD_Inference_AVX512.obj" ^
    /out:"%OUT_DIR%\RawrXD_IDE_Native.exe" ^
    /entry:WinMain

if errorlevel 1 goto :link_error

echo.
echo ==========================================
echo  BUILD SUCCESSFUL
echo ==========================================
echo.
echo Output: %OUT_DIR%\RawrXD_IDE_Native.exe
echo.
for %%I in ("%OUT_DIR%\RawrXD_IDE_Native.exe") do (
    echo Size: %%~zI bytes
)
echo.
goto :end

:asm_error
echo.
echo ==========================================
echo  ASSEMBLY ERROR
echo ==========================================
echo.
exit /b 1

:link_error
echo.
echo ==========================================
echo  LINK ERROR
echo ==========================================
echo.
exit /b 1

:end
echo Done.
