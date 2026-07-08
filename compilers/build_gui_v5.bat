@echo off
setlocal enabledelayedexpansion

echo ============================================
echo RawrXD GUI IDE v5 Build (Advanced Features)
echo ============================================
echo.

set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "SRC=d:\rawrxd\compilers\RawrXD_GUI_v5.asm"
set "OBJ=RawrXD_GUI_v5.obj"
set "OUT=RawrXD-IDE-v5.exe"

if not exist "%ML64%" (
    echo ERROR: ml64.exe not found at %ML64%
    exit /b 1
)

echo [1/2] Assembling %SRC%...
"%ML64%" /c /W3 /nologo /Zi /Fo %OBJ% "%SRC%"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Assembly failed
    exit /b 1
)
echo       Assembled: %OBJ%

echo [2/2] Linking %OBJ%...
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe /MACHINE:X64 /SUBSYSTEM:WINDOWS /ENTRY:WinMain /OUT:%OUT% %OBJ% "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\user32.lib" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\gdi32.lib" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\comdlg32.lib"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Link failed
    exit /b 1
)
echo       Linked: %OUT%

del %OBJ%

echo.
echo ============================================
echo Build SUCCESS: %OUT%
echo Features: Syntax highlighting, Error parsing, Project files
echo ============================================
exit /b 0
