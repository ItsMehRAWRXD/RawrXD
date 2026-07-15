@echo off
setlocal enabledelayedexpansion

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "WINSDK_PATH=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.22621.0"

set "LINK=%MASM_PATH%\link.exe"

set "BUILD_DIR=d:\rawrxd\build-master"
set "OUT_DIR=%BUILD_DIR%\bin"

set "LIB_PATH=%MASM_PATH%\lib\x64"
set "LIB_PATH=%LIB_PATH%;%WINSDK_PATH%\Lib\%WINSDK_VER%\um\x64"
set "LIB_PATH=%LIB_PATH%;%WINSDK_PATH%\Lib\%WINSDK_VER%\ucrt\x64"

echo [LINK] Linking RawrXD_Full.dll with all components...

REM Build object file list
cd /d "%BUILD_DIR%"
set "OBJ_LIST="
for %%f in (*.obj) do (
    set "OBJ_LIST=!OBJ_LIST! "%%BUILD_DIR%%\%%f""
)

echo Objects: !OBJ_LIST!

"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /LIBPATH:"%LIB_PATH%" /OUT:"%OUT_DIR%\RawrXD_Full.dll" /PDB:"%OUT_DIR%\RawrXD_Full.pdb" *.obj kernel32.lib user32.lib gdi32.lib advapi32.lib shell32.lib ole32.lib /SUBSYSTEM:WINDOWS /MACHINE:X64 /LARGEADDRESSAWARE

echo Exit: %ERRORLEVEL%
