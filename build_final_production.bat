@echo off
set "ML_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "SRC_DIR=D:\rawrxd\src"
set "OBJ_DIR=D:\rawrxd\obj"
set "BIN_OUT=D:\rawrxd\Sovereign_Engine.exe"
set "LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"

if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"

echo [BUILD] Compiling Titan Core and Sovereign Modules...

:: 1. Compile Titan (Core)
"%ML_PATH%" /nologo /c /Fo"%OBJ_DIR%\Titan.obj" /I"%SRC_DIR%" "%SRC_DIR%\RawrXD_Titan_Master_GodSource.asm"

:: 1.5. Compile Prompt Engine
"%ML_PATH%" /nologo /c /Fo"%OBJ_DIR%\RawrXD_DynamicPromptEngine.obj" /I"%SRC_DIR%" "%SRC_DIR%\asm\RawrXD_DynamicPromptEngine.asm"
"%ML_PATH%" /nologo /c /Fo"%OBJ_DIR%\RawrXD_DynamicPromptEngine_Templates.obj" /I"%SRC_DIR%" "%SRC_DIR%\asm\RawrXD_DynamicPromptEngine_Templates.asm"

:: 2. Compile Sovereign Modules (Logic)
set "modules=IPC Finisher Governor Ticker Watchdog Monitor Alpha SwarmLink Debugger Teardown Wire Telemetry_Engine Bridge Binary Resilience Log GGUF"
for %%m in (%modules%) do (
    if exist "%SRC_DIR%\Sovereign_%%m.asm" (
        "%ML_PATH%" /nologo /c /Fo"%OBJ_DIR%\Sovereign_%%m.obj" /I"%SRC_DIR%" "%SRC_DIR%\Sovereign_%%m.asm"
    )
)

echo [BUILD] Linking Final Monolith...
"%LINK_PATH%" /nologo /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:"%BIN_OUT%" "%OBJ_DIR%\*.obj" kernel32.lib ws2_32.lib

if errorlevel 1 goto :fail
echo [BUILD] SUCCESS: %BIN_OUT% generated.
exit /b 0

:fail
echo [BUILD] FAILED.
exit /b 1