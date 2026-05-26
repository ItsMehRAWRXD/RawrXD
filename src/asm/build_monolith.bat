@echo off
setlocal EnableDelayedExpansion

set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "ASM_SRC=d:\rawrxd\src\asm"
set "SRC_DIR=d:\rawrxd\src"
set "OUT_DIR=d:\rawrxd\build"

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"
del /q "%OUT_DIR%\*.obj"
cd /d "%ASM_SRC%"

echo [SOVEREIGN] Starting Monolithic Assembly...

:: Assemble the Monolith and Dispatch first (explicit OBJ names)
"%ML64%" /c /nologo /W3 /Zi /Fo"%OUT_DIR%\Sovereign_Monolith.obj" /I"%ASM_SRC%" "Sovereign_Monolith.asm"
"%ML64%" /c /nologo /W3 /Zi /Fo"%OUT_DIR%\Sovereign_Cyclic_Dispatch.obj" /I"%ASM_SRC%" "Sovereign_Cyclic_Dispatch.asm"
"%ML64%" /c /nologo /W3 /Zi /Fo"%OUT_DIR%\Sovereign_PEB_Loader.obj" /I"%ASM_SRC%" "%SRC_DIR%\Sovereign_PEB_Loader.asm"

:: Assemble remaining Kernels
for %%f in (Sovereign_AES_Cache_Pulse.asm Sovereign_API_Bridge.asm Sovereign_Bootstrap_Core.asm Sovereign_Audit_Circular_Buffer.asm) do (
    if exist "%%f" (
        "%ML64%" /c /nologo /W3 /Zi /Fo"%OUT_DIR%\%%~nf.obj" /I"%ASM_SRC%" "%%f"
    )
)

echo [SOVEREIGN] Linking Monolith...

"%LINK%" /nologo /SUBSYSTEM:CONSOLE /ENTRY:Sovereign_Entry /NODEFAULTLIB /OUT:"%OUT_DIR%\Sovereign_Engine_Monolith.exe" "%OUT_DIR%\*.obj" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\ntdll.lib"

if %ERRORLEVEL% equ 0 echo [SUCCESS] Sovereign_Engine_Monolith.exe Built.
exit /b %ERRORLEVEL%
