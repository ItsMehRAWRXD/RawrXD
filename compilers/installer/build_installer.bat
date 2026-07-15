@echo off
setlocal enabledelayedexpansion

echo ============================================
echo RawrXD Toolchain Installer Builder
echo ============================================
echo.

set "SOURCE_DIR=d:\rawrxd\compilers"
set "BUILD_DIR=d:\rawrxd\compilers\installer\build"
set "OUTPUT_DIR=d:\rawrxd\compilers\installer\output"

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo [1/5] Preparing installation files...

REM Create directory structure
if not exist "%BUILD_DIR%\bin" mkdir "%BUILD_DIR%\bin"
if not exist "%BUILD_DIR%\docs" mkdir "%BUILD_DIR%\docs"
if not exist "%BUILD_DIR%\examples" mkdir "%BUILD_DIR%\examples"

echo [2/5] Copying executables...
copy "%SOURCE_DIR%\native_toolchain\rawrxd_native_assembler.exe" "%BUILD_DIR%\bin\" >nul
copy "%SOURCE_DIR%\native_toolchain\rawrxd_native_linker_v2.exe" "%BUILD_DIR%\bin\" >nul
copy "%SOURCE_DIR%\native_toolchain\c_compiler_working.exe" "%BUILD_DIR%\bin\" >nul
copy "%SOURCE_DIR%\rawrxd_ide_cli_v3.bat" "%BUILD_DIR%\bin\" >nul
copy "%SOURCE_DIR%\RawrXD-IDE-v5.exe" "%BUILD_DIR%\bin\" >nul

echo [3/5] Copying language compilers...
copy "%SOURCE_DIR%\real_compilers\python_compiler_real.exe" "%BUILD_DIR%\bin\" >nul
copy "%SOURCE_DIR%\real_compilers\javascript_compiler_real.exe" "%BUILD_DIR%\bin\" >nul
copy "%SOURCE_DIR%\real_compilers\bash_compiler_real.exe" "%BUILD_DIR%\bin\" >nul
copy "%SOURCE_DIR%\real_compilers\powershell_compiler_real.exe" "%BUILD_DIR%\bin\" >nul
copy "%SOURCE_DIR%\real_compilers\csharp_compiler_real.exe" "%BUILD_DIR%\bin\" >nul
copy "%SOURCE_DIR%\real_compilers\java_compiler_real.exe" "%BUILD_DIR%\bin\" >nul
copy "%SOURCE_DIR%\real_compilers\eon_compiler_real.exe" "%BUILD_DIR%\bin\" >nul

echo [4/5] Copying documentation...
copy "%SOURCE_DIR%\docs\USER_MANUAL.md" "%BUILD_DIR%\docs\" >nul
copy "%SOURCE_DIR%\README.md" "%BUILD_DIR%\" >nul 2>nul

echo [5/5] Creating examples...
echo ; Hello World in Assembly > "%BUILD_DIR%\examples\hello.asm"
echo _start: >> "%BUILD_DIR%\examples\hello.asm"
echo     mov rax, 42 >> "%BUILD_DIR%\examples\hello.asm"
echo     ret >> "%BUILD_DIR%\examples\hello.asm"

echo // Hello World in C > "%BUILD_DIR%\examples\hello.c"
echo int main() { >> "%BUILD_DIR%\examples\hello.c"
echo     return 42; >> "%BUILD_DIR%\examples\hello.c"
echo } >> "%BUILD_DIR%\examples\hello.c"

echo # Hello World in Python > "%BUILD_DIR%\examples\hello.py"
echo print("Hello from Python!") >> "%BUILD_DIR%\examples\hello.py"

echo ; Creating portable archive...
powershell -Command "Compress-Archive -Path '%BUILD_DIR%\*' -DestinationPath '%OUTPUT_DIR%\RawrXD-Toolchain-v1.0.zip' -Force"

echo.
echo ============================================
echo Installer package created!
echo Location: %OUTPUT_DIR%\RawrXD-Toolchain-v1.0.zip
echo Contents:
dir /s /b "%BUILD_DIR%"
echo ============================================
exit /b 0
