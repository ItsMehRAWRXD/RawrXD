@echo off
set "MINGW=C:\ProgramData\mingw64\mingw64\bin"
set "PATH=%MINGW%;%PATH%"
set "OUT=D:\rawrxd-ci-bootstrap\out"
set "REL=D:\rawrxd-ci-bootstrap\release"

echo === LINK SovereignIDE.exe ===
g++ -o "%REL%\SovereignIDE.exe" "%OUT%\SovereignIDE.o" -lwinhttp -lws2_32 -ladvapi32 -lshell32 -lole32 -lshlwapi -lcrypt32 -lbcrypt -lpsapi -lpdh -lwinmm -ldxgi -ld3d11 -lgdi32 -static -mconsole -municode
if %ERRORLEVEL% EQU 0 (
    echo SUCCESS: release\SovereignIDE.exe
) else (
    echo LINK FAILED
    exit /b 1
)
