@echo off
cd /d D:\rawrxd-ci-bootstrap

echo Building SovereignChatClient.exe...

"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /W3 /nologo /Zi /Fo SovereignChatClient.obj SovereignChatClient.asm
if errorlevel 1 (
    echo Assembly failed
    exit /b 1
)

"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe" /SUBSYSTEM:CONSOLE /ENTRY:main /NODEFAULTLIB /OUT:SovereignChatClient.exe SovereignChatClient.obj kernel32.lib
if errorlevel 1 (
    echo Link failed
    exit /b 1
)

echo Build successful!
dir SovereignChatClient.exe
