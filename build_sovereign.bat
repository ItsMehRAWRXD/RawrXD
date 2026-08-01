@echo off
set "MINGW=C:\ProgramData\mingw64\mingw64\bin"
set "PATH=%MINGW%;%PATH%"
set "SRC=D:\rawrxd-ci-bootstrap\src"
set "OUT=D:\rawrxd-ci-bootstrap\out"
set "REL=D:\rawrxd-ci-bootstrap\release"

echo ================================================================================
echo BUILDING SOVEREIGN IDE — Zero-Dependency Native Inference Platform
echo ================================================================================

if not exist "%OUT%" mkdir "%OUT%"
if not exist "%REL%" mkdir "%REL%"

echo [COMPILE] SovereignIDE.cpp
g++ -c -std=c++20 -O2 -mavx2 -mfma ^
    -Isrc -Isrc\engine -Isrc\orchestration -Isrc\metrics -Isrc\ui -Isrc\security ^
    -o "%OUT%\SovereignIDE.o" "%SRC%\SovereignIDE.cpp"
if %ERRORLEVEL% NEQ 0 (
    echo COMPILATION FAILED
    exit /b 1
)
echo OK

echo [LINK] SovereignIDE.exe
g++ -o "%REL%\SovereignIDE.exe" ^
    "%OUT%\SovereignIDE.o" ^
    -lwinmm -ldxgi -ld3d11 -lgdi32 -lwinhttp -lws2_32 -ladvapi32 -lshell32 -lole32 -lshlwapi -lcrypt32 -lbcrypt -lpsapi -lpdh -static -mconsole -municode -municode

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ================================================================================
    echo SUCCESS: release\SovereignIDE.exe built
    echo ================================================================================
) else (
    echo LINK FAILED
    exit /b 1
)
