@echo off
setlocal enabledelayedexpansion

echo [LINK] RawrXD Full Build - From Debug Pipeline
echo ================================================

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "LINK=%MASM_PATH%\link.exe"

set "BUILD_DIR=d:\rawrxd\build-master"
set "OUT_DIR=%BUILD_DIR%\bin"

set "LIB_PATH=%MASM_PATH%\lib\x64"

REM MUST run from debug-pipeline directory
cd /d d:\rawrxd\build-debug-pipeline

echo Running from: %CD%
echo.

REM Build object list
cd /d "%BUILD_DIR%"
set "OBJ_LIST="
for %%f in (*.obj) do (
    set "OBJ_LIST=!OBJ_LIST! "%BUILD_DIR%\%%f""
)
cd /d d:\rawrxd\build-debug-pipeline

echo Linking with %LINK%
echo.

"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain /LIBPATH:"%LIB_PATH%" /OUT:"%OUT_DIR%\RawrXD_Full.dll" /PDB:"%OUT_DIR%\RawrXD_Full.pdb" !OBJ_LIST! kernel32.lib user32.lib gdi32.lib advapi32.lib shell32.lib ole32.lib /SUBSYSTEM:WINDOWS /MACHINE:X64 /LARGEADDRESSAWARE

set "LINK_RESULT=%ERRORLEVEL%"
echo.
echo Exit code: %LINK_RESULT%

if exist "%OUT_DIR%\RawrXD_Full.dll" (
    echo [SUCCESS] Built: %OUT_DIR%\RawrXD_Full.dll
    for %%F in ("%OUT_DIR%\RawrXD_Full.dll") do echo [SIZE] %%~zF bytes
) else (
    echo [ERROR] DLL not created
)

endlocal
