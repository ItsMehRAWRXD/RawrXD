@echo off
REM RawrXD Beacon Debugger Build Script
REM Pure x64 MASM, Zero CRT, Zero External Dependencies

echo ============================================
echo RawrXD Beacon Debugger Build
echo ============================================

set ML64="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.40.33807\bin\Hostx64\x64\ml64.exe"
if not exist %ML64% (
    set ML64="C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.29.30133\bin\Hostx64\x64\ml64.exe"
)
if not exist %ML64% (
    for /f "delims=" %%a in ('where ml64.exe 2^>nul') do set ML64="%%a"
)

if not exist %ML64% (
    echo ERROR: ml64.exe not found. Install Visual Studio Build Tools.
    exit /b 1
)

echo [+] Using assembler: %ML64%

REM Assemble
echo [+] Assembling RawrXD_BeaconDebugger.asm...
%ML64% /c /nologo /W3 /Fo beacon.obj /Fl beacon.lst RawrXD_BeaconDebugger.asm
if errorlevel 1 (
    echo ERROR: Assembly failed
    exit /b 1
)

REM Link
echo [+] Linking beacon.exe...
link /nologo /subsystem:console /entry:main /out:beacon.exe beacon.obj kernel32.lib ntdll.lib
if errorlevel 1 (
    echo ERROR: Link failed
    exit /b 1
)

echo [+] Build complete: beacon.exe
echo [+] Size:
dir /-C beacon.exe | findstr beacon.exe
