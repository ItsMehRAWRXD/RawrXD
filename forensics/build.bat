@echo off
echo Building GGUF Forensics Tool...
echo.

set CXX=g++
set CXXFLAGS=-std=c++17 -O2 -Wall -Wextra
set SOURCES=gguf_forensics.cpp gguf_types.cpp
set OUTPUT=gguf_forensics.exe

%CXX% %CXXFLAGS% %SOURCES% -o %OUTPUT%

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Build successful: %OUTPUT%
    echo.
    echo Usage: %OUTPUT% ^<file.gguf^> [options]
    echo   --metadata    Show all metadata
    echo   --verify      Check alignment
    echo   --tensor ^<n^>  Analyze specific tensor
    echo   --entropy     Calculate entropy
    echo   --hex         Hex dump
) else (
    echo Build failed!
    exit /b 1
)
