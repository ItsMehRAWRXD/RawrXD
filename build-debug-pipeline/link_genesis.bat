@echo off
setlocal enabledelayedexpansion

echo [LINK] RawrXD Full Build - Using VS2022 Linker
echo ================================================

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "WINSDK_PATH=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.22621.0"

set "LINK=%MASM_PATH%\link.exe"

set "BUILD_DIR=d:\rawrxd\build-master"
set "OUT_DIR=%BUILD_DIR%\bin"

set "LIB_PATH=%MASM_PATH%\lib\x64"

REM Build object list from build-master directory
cd /d "%BUILD_DIR%"
set "OBJ_LIST="
for %%f in (*.obj) do (
    set "OBJ_LIST=!OBJ_LIST! "%BUILD_DIR%\%%f""
)

echo Objects: !OBJ_LIST!
echo.

REM MUST run from debug-pipeline directory to avoid STATUS_DLL_NOT_FOUND
cd /d d:\rawrxd\build-debug-pipeline

echo Running linker from: %CD%
echo.

"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /NOENTRY ^
    /LIBPATH:"%LIB_PATH%" ^
    /LIBPATH:"%WINSDK_PATH%\Lib\%WINSDK_VER%\um\x64" ^
    /LIBPATH:"%WINSDK_PATH%\Lib\%WINSDK_VER%\ucrt\x64" ^
    /OUT:"%OUT_DIR%\RawrXD_Full.dll" ^
    /PDB:"%OUT_DIR%\RawrXD_Full.pdb" ^
    !OBJ_LIST! ^
    kernel32.lib user32.lib gdi32.lib advapi32.lib shell32.lib ole32.lib ^
    /SUBSYSTEM:WINDOWS /MACHINE:X64 /LARGEADDRESSAWARE

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
