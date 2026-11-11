@echo off
title RawrXD Agentic IDE
echo.
echo     ██████╗  █████╗ ██╗    ██╗██████╗ ██╗  ██╗██████╗ 
echo     ██╔══██╗██╔══██╗██║    ██║██╔══██╗╚██╗██╔╝██╔══██╗
echo     ██████╔╝███████║██║ █╗ ██║██████╔╝ ╚███╔╝ ██║  ██║
echo     ██╔══██╗██╔══██║██║███╗██║██╔══██╗ ██╔██╗ ██║  ██║
echo     ██║  ██║██║  ██║╚███╔███╔╝██║  ██║██╔╝ ██╗██████╔╝
echo     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
echo.
echo     Agentic IDE - 2x Faster Than Cloud Solutions
echo.

cd /d "%~dp0"

if not exist "bin\RawrXD-Win32IDE.exe" (
    echo ERROR: RawrXD-Win32IDE.exe not found!
    echo Please ensure the IDE is properly installed.
    pause
    exit /b 1
)

echo Launching RawrXD IDE...
start "" "bin\RawrXD-Win32IDE.exe"
echo.
echo IDE launched successfully!
timeout /t 3 >nul
