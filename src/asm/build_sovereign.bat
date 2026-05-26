@echo off
setlocal EnableDelayedExpansion

set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINKER=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "ASM_SRC=D:\rawrxd\src\asm"
set "SRC_DIR=D:\rawrxd\src"
set "OUT_DIR=D:\rawrxd\build"

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"
del /q "%OUT_DIR%\*.obj"
cd /d "%ASM_SRC%"

echo [BUILD] Core Modules...
"%ML64%" /c /nologo /I"%SRC_DIR%" /Fo"%OUT_DIR%\Main.obj" /I"%ASM_SRC%" "%SRC_DIR%\Sovereign_Main.asm"
"%ML64%" /c /nologo /I"%SRC_DIR%" /Fo"%OUT_DIR%\PEB.obj" /I"%ASM_SRC%" "%SRC_DIR%\Sovereign_PEB_Loader.asm"
"%ML64%" /c /nologo /I"%SRC_DIR%" /Fo"%OUT_DIR%\Heap.obj" /I"%ASM_SRC%" "%SRC_DIR%\Sovereign_Heap.asm"
"%ML64%" /c /nologo /I"%SRC_DIR%" /Fo"%OUT_DIR%\Model.obj" /I"%ASM_SRC%" "%SRC_DIR%\Sovereign_Model_Loader.asm"
"%ML64%" /c /nologo /I"%SRC_DIR%" /Fo"%OUT_DIR%\Reg.obj" /I"%ASM_SRC%" "Sovereign_Registry_Manager.asm"
"%ML64%" /c /nologo /I"%SRC_DIR%" /Fo"%OUT_DIR%\Scan.obj" /I"%ASM_SRC%" "%SRC_DIR%\Sovereign_SIMD_Scanner.asm"
"%ML64%" /c /nologo /I"%SRC_DIR%" /Fo"%OUT_DIR%\Hardware.obj" /I"%ASM_SRC%" "%SRC_DIR%\Sovereign_Hardware.asm"
"%ML64%" /c /nologo /I"%SRC_DIR%" /Fo"%OUT_DIR%\Compute.obj" /I"%ASM_SRC%" "%SRC_DIR%\Sovereign_Compute_Kernels.asm"
"%ML64%" /c /nologo /I"%SRC_DIR%" /Fo"%OUT_DIR%\Globals.obj" /I"%ASM_SRC%" "%SRC_DIR%\Sovereign_Globals.asm"
"%ML64%" /c /nologo /I"%SRC_DIR%" /Fo"%OUT_DIR%\Kernels.obj" /I"%ASM_SRC%" "%SRC_DIR%\Sovereign_Kernels.asm"

echo [LINK] Creating Sovereign_Engine.exe...
"%LINKER%" /nologo /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /NODEFAULTLIB /LARGEADDRESSAWARE /OUT:"%OUT_DIR%\Sovereign_Engine.exe" "%OUT_DIR%\Main.obj" "%OUT_DIR%\PEB.obj" "%OUT_DIR%\Heap.obj" "%OUT_DIR%\Model.obj" "%OUT_DIR%\Reg.obj" "%OUT_DIR%\Scan.obj" "%OUT_DIR%\Hardware.obj" "%OUT_DIR%\Compute.obj" "%OUT_DIR%\Globals.obj" "%OUT_DIR%\Kernels.obj"

if exist "%OUT_DIR%\Sovereign_Engine.exe" (
    echo [SUCCESS] Elite Engine Built: %OUT_DIR%\Sovereign_Engine.exe
    echo [EXECUTE] Starting Sovereign Engine...
    "%OUT_DIR%\Sovereign_Engine.exe"
) else (
    echo [ERROR] Build Failed.
)