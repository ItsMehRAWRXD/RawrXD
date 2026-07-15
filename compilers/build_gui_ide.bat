@echo off
setlocal enabledelayedexpansion

echo ============================================
echo RawrXD GUI IDE Build (Wired)
echo ============================================
echo.

set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "SRC=d:\rawrxd\compilers\RawrXD_GUI_Wired.asm"
set "OBJ=RawrXD_GUI_Wired.obj"
set "OUT=RawrXD-IDE-Wired.exe"

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
"%LINK%" /SUBSYSTEM:WINDOWS /OUT:%OUT% %OBJ% kernel32.lib user32.lib gdi32.lib
if %ERRORLEVEL% neq 0 (
    echo ERROR: Link failed
    exit /b 1
)
echo       Linked: %OUT%

del %OBJ%

echo.
echo ============================================
echo Build SUCCESS: %OUT%
echo ============================================
exit /b 0
