@echo off
setlocal

echo Building MinimalChat.exe...

set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe

cd /d D:\rawrxd-ci-bootstrap

echo [1/2] Assembling...
"%ML64%" /c /W3 /nologo /Zi /Fo MinimalChat.obj MinimalChat.asm
if errorlevel 1 (
    echo Assembly failed!
    exit /b 1
)

echo [2/2] Linking...
"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:main /NODEFAULTLIB /OUT:MinimalChat.exe MinimalChat.obj kernel32.lib
if errorlevel 1 (
    echo Link failed!
    exit /b 1
)

echo Build successful!
dir MinimalChat.exe

endlocal
