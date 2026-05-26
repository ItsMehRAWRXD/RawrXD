@echo off
setlocal EnableDelayedExpansion
set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "ASM_SRC=d:\rawrxd\src\asm"
set "OUT_DIR=d:\rawrxd\build"
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"
del /q "%OUT_DIR%\*.obj"
cd /d "%ASM_SRC%"

echo [SOVEREIGN] Building Component: Monolith
"%ML64%" /c /nologo /Fo"%OUT_DIR%\Sovereign_Monolith.obj" "Sovereign_Monolith.asm"
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [SOVEREIGN] Linking Monolith Only...
"%LINK%" /nologo /SUBSYSTEM:CONSOLE /ENTRY:Sovereign_Entry /NODEFAULTLIB /OUT:"%OUT_DIR%\Sovereign_Engine_Monolith.exe" "%OUT_DIR%\Sovereign_Monolith.obj" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\ntdll.lib"
if %ERRORLEVEL% equ 0 echo [SUCCESS] Monolith Link Passed.
exit /b %ERRORLEVEL%
