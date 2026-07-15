@echo off
setlocal enabledelayedexpansion

echo [LINK] RawrXD Full Build - All 40 Objects
echo ==========================================

set "BUILD_DIR=d:\rawrxd\build-master"
set "OUT_DIR=%BUILD_DIR%\bin"

REM Build full object list
set "OBJ_LIST="
for %%f in ("%BUILD_DIR%\*.obj") do (
    set "OBJ_LIST=!OBJ_LIST! "%%f""
)

echo Objects to link: !OBJ_LIST!
echo.

REM Use the link.exe from VS2022 directly
cd /d d:\rawrxd\build-debug-pipeline

C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe /DLL /DEBUG /INCREMENTAL:NO /NOENTRY /OUT:"%OUT_DIR%\RawrXD_Full.dll" /PDB:"%OUT_DIR%\RawrXD_Full.pdb" !OBJ_LIST! kernel32.lib user32.lib gdi32.lib advapi32.lib shell32.lib ole32.lib /SUBSYSTEM:WINDOWS /MACHINE:X64 /LARGEADDRESSAWARE 2> link_errors.txt

echo Exit: %ERRORLEVEL%

if exist "%OUT_DIR%\RawrXD_Full.dll" (
    echo [SUCCESS] Built: %OUT_DIR%\RawrXD_Full.dll
    for %%F in ("%OUT_DIR%\RawrXD_Full.dll") do echo [SIZE] %%~zF bytes
) else (
    echo [ERROR] DLL not found
    type link_errors.txt 2>nul
)

endlocal
