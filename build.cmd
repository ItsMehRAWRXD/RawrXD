@echo off
REM Unified RawrXD Build Script
REM Builds C/ASM files using the native toolchain

set TOOLCHAIN=%~dp0\native_toolchain
set SOURCE=%1
set OUTPUT=%2

if "%SOURCE%"=="" (
    echo Usage: build ^<source.c^> [output.exe]
    exit /b 1
)

if "%OUTPUT%"=="" (
    set OUTPUT=%SOURCE:.c=.exe%
    set OUTPUT=%OUTPUT:.asm=.exe%
)

echo 🔨 Building %SOURCE%...

if "%SOURCE:~-2%"==".c" (
    "%TOOLCHAIN%\universal_compiler.exe" "%SOURCE%" -o "%OUTPUT%"
) else if "%SOURCE:~-4%"==".asm" (
    "%TOOLCHAIN%\minimal_assembler_v7.exe" "%SOURCE%" "%OUTPUT%.obj"
    "%TOOLCHAIN%\linker_fixed.exe" "%OUTPUT%.obj" /out:"%OUTPUT%" /subsystem:3
) else (
    echo Unknown file type: %SOURCE%
    exit /b 1
)

if %ERRORLEVEL%==0 (
    echo ✅ Build successful: %OUTPUT%
) else (
    echo ❌ Build failed
)

exit /b %ERRORLEVEL%
