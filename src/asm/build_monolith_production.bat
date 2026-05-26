@echo off
set ML64="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set LINK="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"

echo [Sovereign] Assembling Stealth Monolith...
%ML64% /c /W3 /nologo /Zi /Fo Sovereign_Monolith_Production.obj Sovereign_Monolith.asm

echo [Sovereign] Linking Monolith (Zero-IAT/No-CRT)...
%LINK% /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /NODEFAULTLIB /LARGEADDRESSAWARE:NO ^
  /OUT:Sovereign_Monolith.exe Sovereign_Monolith_Production.obj

if %ERRORLEVEL% EQU 0 (
    echo [Sovereign] Production Build SUCCESS: Sovereign_Monolith.exe
) else (
    echo [Sovereign] Build FAILED.
)
pause
