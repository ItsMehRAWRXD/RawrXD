@echo off
setlocal enabledelayedexpansion

echo ==============================================================================
echo MASM Editor Pipeline Linker
echo ==============================================================================

call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1

if errorlevel 1 (
    echo [ERROR] Failed to initialize VS environment
    exit /b 1
)

echo [LINK] Environment initialized

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "SRC_DIR=d:\rawrxd\src\asm"
set "BUILD_DIR=d:\rawrxd\build-editor-pipeline"
set "OUT_DIR=%BUILD_DIR%\bin"

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

echo [ASM] Assembling dllmain.asm...
"%MASM_PATH%\ml64.exe" /c /Zi /Zf /W3 /nologo /Fo"%BUILD_DIR%\dllmain.obj" "%SRC_DIR%\dllmain.asm"
if errorlevel 1 (
    echo [ERROR] Failed to assemble dllmain.asm
    exit /b 1
)

echo [ASM] Assembling winmain.asm...
"%MASM_PATH%\ml64.exe" /c /Zi /Zf /W3 /nologo /Fo"%BUILD_DIR%\winmain.obj" "%SRC_DIR%\winmain.asm"
if errorlevel 1 (
    echo [ERROR] Failed to assemble winmain.asm
    exit /b 1
)

echo [LINK] Linking editor_pipeline.dll...

link.exe /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain ^
    /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" ^
    /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" ^
    /OUT:"%OUT_DIR%\editor_pipeline.dll" ^
    "%BUILD_DIR%\dllmain.obj" ^
    "%BUILD_DIR%\input_handler.obj" ^
    "%BUILD_DIR%\wndproc_input_bridge.obj" ^
    "%BUILD_DIR%\editor.obj" ^
    "%BUILD_DIR%\memory.obj" ^
    user32.lib kernel32.lib gdi32.lib

if errorlevel 1 (
    echo [ERROR] Linker failed with exit code %ERRORLEVEL%
    exit /b 1
)

echo [LINK] Linking editor_pipeline.exe...

link.exe /SUBSYSTEM:WINDOWS /DEBUG /INCREMENTAL:NO /ENTRY:WinMain ^
    /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" ^
    /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" ^
    /OUT:"%OUT_DIR%\editor_pipeline.exe" ^
    "%BUILD_DIR%\winmain.obj" ^
    "%BUILD_DIR%\dllmain.obj" ^
    "%BUILD_DIR%\input_handler.obj" ^
    "%BUILD_DIR%\wndproc_input_bridge.obj" ^
    "%BUILD_DIR%\editor.obj" ^
    "%BUILD_DIR%\memory.obj" ^
    user32.lib kernel32.lib gdi32.lib

if errorlevel 1 (
    echo [ERROR] Linker failed with exit code %ERRORLEVEL%
    exit /b 1
)

echo [SUCCESS] Build complete
dir "%OUT_DIR%\*.dll" "%OUT_DIR%\*.exe" 2>nul

endlocal