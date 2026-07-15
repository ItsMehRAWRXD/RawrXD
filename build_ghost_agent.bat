@echo off
REM Build RawrXD Ghost Text Agent
REM One command to rule them all - with ghost text and autonomous execution

echo ============================================
echo  Building RawrXD Ghost Text Agent
echo ============================================
echo.

set SRC_DIR=d:\rawrxd\src
set OUT_DIR=d:\rawrxd\bin

if not exist %OUT_DIR% mkdir %OUT_DIR%

cd /d %SRC_DIR%

echo Compiling ghost text engine...
echo.

cl /EHsc /std:c++17 /O2 /Fe:%OUT_DIR%\rawrxd.exe ^
    rawrxd_main.cpp ^
    agentic\ghost_text_engine.cpp ^
    agentic\autonomous_agent.cpp ^
    /I. ^
    /Iagentic ^
    /D_CRT_SECURE_NO_WARNINGS ^
    kernel32.lib user32.lib gdi32.lib

if exist %OUT_DIR%\rawrxd.exe (
    echo.
    echo ============================================
    echo  ✅ Build successful!
    echo ============================================
    echo.
    echo Usage:
    echo   rawrxd                    - Interactive ghost text mode
    echo   rawrxd "compile hello.c"  - Execute request
    echo.
    echo Examples:
    echo   rawrxd "compile test.c and run it"
    echo   rawrxd "patch test.exe to return 0"
    echo   rawrxd "analyze malware.exe"
    echo   rawrxd "disassemble app.exe"
    echo   rawrxd "reverse engineer this binary"
    echo.
    echo Try it now:
    echo   %OUT_DIR%\rawrxd.exe
    echo.
) else (
    echo.
    echo ============================================
    echo  ❌ Build failed
    echo ============================================
    echo.
)
