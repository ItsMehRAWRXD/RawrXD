@echo off
REM RawrXD Codex Build Script
REM Zero-dependency native Windows build

setlocal enabledelayedexpansion

REM Configuration
set BUILD_TYPE=Release
set OUTPUT_DIR=build

REM Detect compiler
where cl >nul 2>&1
if %errorlevel% == 0 (
    echo Detected: MSVC (cl)
    set COMPILER=msvc
) else (
    where g++ >nul 2>&1
    if %errorlevel% == 0 (
        echo Detected: MinGW (g++)
        set COMPILER=mingw
    ) else (
        echo Error: No compiler found. Install Visual Studio or MinGW.
        exit /b 1
    )
)

REM Create output directory
if not exist %OUTPUT_DIR% mkdir %OUTPUT_DIR%

REM Source files
set SOURCES=main.cpp CodexCLI.cpp CodexGUI.cpp HttpClient.cpp

REM Include paths
set INCLUDES=-I. -I..\..\include

if "%COMPILER%"=="msvc" (
    echo Building with MSVC...
    
    REM Compile
    cl.exe /c /O2 /W4 /EHsc /MT /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE ^
        %INCLUDES% ^
        main.cpp CodexCLI.cpp CodexGUI.cpp HttpClient.cpp
    
    if !errorlevel! neq 0 (
        echo Compilation failed!
        exit /b 1
    )
    
    REM Link
    link.exe /OUT:%OUTPUT_DIR%\rawrxd-codex.exe ^
        /SUBSYSTEM:WINDOWS /ENTRY:wmainCRTStartup ^
        main.obj CodexCLI.obj CodexGUI.obj HttpClient.obj ^
        winhttp.lib user32.lib gdi32.lib shell32.lib comctl32.lib
    
    if !errorlevel! neq 0 (
        echo Linking failed!
        exit /b 1
    )
    
    REM Clean up
    del *.obj
    
) else if "%COMPILER%"=="mingw" (
    echo Building with MinGW...
    
    g++ -std=c++17 -O3 -Wall -Wextra -mwindows -municode -static ^
        %INCLUDES% ^
        %SOURCES% ^
        -o %OUTPUT_DIR%\rawrxd-codex.exe ^
        -lwinhttp -luser32 -lgdi32 -lshell32 -lcomctl32 ^
        -static-libgcc -static-libstdc++
    
    if !errorlevel! neq 0 (
        echo Build failed!
        exit /b 1
    )
)

echo.
echo Build complete: %OUTPUT_DIR%\rawrxd-codex.exe

REM Show file info
if exist %OUTPUT_DIR%\rawrxd-codex.exe (
    echo.
    dir %OUTPUT_DIR%\rawrxd-codex.exe | findstr "rawrxd-codex"
)

endlocal
