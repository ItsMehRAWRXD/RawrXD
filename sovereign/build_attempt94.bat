@echo off
REM Attempt 94: Minimal Sovereign Substrate Baseline
set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
set LIBPATH_UM="C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"

echo [Attempt 94] Sovereign Substrate Baseline
echo ===========================================

echo [1/3] Assembling Sovereign_Linker_Glue...
"%ML64%" /nologo /c /Fo "D:\rawrxd\sovereign\Sovereign_Linker_Glue.obj" "D:\rawrxd\sovereign\Sovereign_Linker_Glue.asm"
if %errorlevel% neq 0 (echo FAILED && exit /b 1)

echo [2/3] Assembling Sovereign_IPC_Ingest...
"%ML64%" /nologo /c /Fo "D:\rawrxd\sovereign\Sovereign_IPC_Ingest.obj" "D:\rawrxd\sovereign\Sovereign_IPC_Ingest.asm"
if %errorlevel% neq 0 (echo FAILED && exit /b 1)

echo [3/3] Assembling Sovereign_Bridge...
"%ML64%" /nologo /c /Fo "D:\rawrxd\sovereign\Sovereign_Bridge.obj" "D:\rawrxd\sovereign\Sovereign_Bridge.asm"
if %errorlevel% neq 0 (echo FAILED && exit /b 1)

echo [4/4] Linking...
"%LINK%" /NODEFAULTLIB /ENTRY:Sovereign_EntryPoint /SUBSYSTEM:WINDOWS ^
    /OUT:"D:\rawrxd\RawrXD_Sovereign_Attempt94.exe" ^
    "D:\rawrxd\sovereign\Sovereign_Linker_Glue.obj" ^
    "D:\rawrxd\sovereign\Sovereign_IPC_Ingest.obj" ^
    "D:\rawrxd\sovereign\Sovereign_Bridge.obj" ^
    /LIBPATH:%LIBPATH_UM% ^
    kernel32.lib user32.lib ^
    > "D:\rawrxd\sovereign\link_results.txt" 2>&1

if %errorlevel% equ 0 (
    echo.
    echo ==========================================
    echo BUILD SUCCESS - Attempt 94
    echo ==========================================
    dir "D:\rawrxd\RawrXD_Sovereign_Attempt94.exe" | findstr /C:".exe"
) else (
    echo LINK FAILED
    type "D:\rawrxd\sovereign\link_results.txt"
    exit /b 1
)
