@echo off
setlocal EnableDelayedExpansion
set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "ASM_SRC=d:\rawrxd\src\asm"
set "OUT_DIR=d:\rawrxd\build"
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"
del /q "%OUT_DIR%\*.obj"
cd /d "%ASM_SRC%"
echo [SOVEREIGN] Starting Pure Monolith Assembly...
:: No Debug info (/Zi) to minimize OBJ complexity
"%ML64%" /c /nologo /W3 /Fo"%OUT_DIR%\Sovereign_Monolith.obj" /I"%ASM_SRC%" "Sovereign_Monolith.asm"
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%
"%ML64%" /c /nologo /W3 /Fo"%OUT_DIR%\Sovereign_Cyclic_Dispatch.obj" /I"%ASM_SRC%" "Sovereign_Cyclic_Dispatch.asm"
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%
"%ML64%" /c /nologo /W3 /Fo"%OUT_DIR%\Sovereign_PEB_Loader.obj" /I"%ASM_SRC%" "Sovereign_PEB_Loader.asm"
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%
echo [SOVEREIGN] Linking Minimum Core...
:: Check file existence before linking
if not exist "%OUT_DIR%\Sovereign_Monolith.obj" echo ERR: Monolith missing && exit /b 1
if not exist "%OUT_DIR%\Sovereign_Cyclic_Dispatch.obj" echo ERR: Dispatch missing && exit /b 1
if not exist "%OUT_DIR%\Sovereign_PEB_Loader.obj" echo ERR: PEB missing && exit /b 1
"%LINK%" /nologo /SUBSYSTEM:CONSOLE /ENTRY:Sovereign_Entry /NODEFAULTLIB /OUT:"%OUT_DIR%\Sovereign_Engine_Monolith.exe" "%OUT_DIR%\Sovereign_Monolith.obj" "%OUT_DIR%\Sovereign_Cyclic_Dispatch.obj" "%OUT_DIR%\Sovereign_PEB_Loader.obj" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\ntdll.lib"
if %ERRORLEVEL% equ 0 echo [SUCCESS] Minimal Core Built.
exit /b %ERRORLEVEL%
