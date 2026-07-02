@echo off
setlocal

echo ========================================
echo   Building SimpleSovereignChat.exe
echo ========================================
echo.

set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe

cd /d D:\rawrxd-ci-bootstrap

echo [1/2] Assembling SimpleSovereignChat.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo SimpleSovereignChat.obj SimpleSovereignChat.asm
if errorlevel 1 (
    echo ❌ Assembly failed!
    exit /b 1
)
echo ✅ Assembly complete

echo.
echo [2/2] Linking SimpleSovereignChat.exe...
"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:SimpleSovereignChat.exe SimpleSovereignChat.obj kernel32.lib
if errorlevel 1 (
    echo ❌ Link failed!
    exit /b 1
)
echo ✅ Link complete

echo.
echo ========================================
echo   Build successful!
echo ========================================
echo.
echo Binary: SimpleSovereignChat.exe
dir SimpleSovereignChat.exe /b

endlocal
