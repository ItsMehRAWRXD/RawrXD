@echo off
setlocal EnableDelayedExpansion
set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "ASM_SRC=d:\rawrxd\src\asm"
set "OUT_DIR=d:\rawrxd\build"
cd /d "%ASM_SRC%"
"%ML64%" /c /nologo /Fo "%OUT_DIR%\Sovereign_Monolith.obj" "Sovereign_Monolith.asm"
"%ML64%" /c /nologo /Fo "%OUT_DIR%\Sovereign_Cyclic_Dispatch.obj" "Sovereign_Cyclic_Dispatch.asm"
"%ML64%" /c /nologo /Fo "%OUT_DIR%\Sovereign_PEB_Loader.obj" "Sovereign_PEB_Loader.asm"
"%LINK%" /nologo /SUBSYSTEM:CONSOLE /ENTRY:Sovereign_Entry /NODEFAULTLIB /OUT:"%OUT_DIR%\Sovereign_Engine_Monolith.exe" "%OUT_DIR%\Sovereign_Monolith.obj" "%OUT_DIR%\Sovereign_Cyclic_Dispatch.obj" "%OUT_DIR%\Sovereign_PEB_Loader.obj" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\ntdll.lib"
if %ERRORLEVEL% equ 0 echo [SUCCESS] Sovereign_Engine_Monolith.exe Built.
