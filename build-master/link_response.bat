@echo off
setlocal enabledelayedexpansion

echo [LINK] RawrXD Full Build - Response File
echo ========================================

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "WINSDK_PATH=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.22621.0"

set "LINK=%MASM_PATH%\link.exe"

set "BUILD_DIR=d:\rawrxd\build-master"
set "OUT_DIR=%BUILD_DIR%\bin"

set "LIB_PATH=%MASM_PATH%\lib\x64"

REM Create response file with all objects
cd /d "%BUILD_DIR%"
echo. > link.rsp
for %%f in (*.obj) do (
    echo "%BUILD_DIR%\%%f" >> link.rsp
)
echo kernel32.lib >> link.rsp
echo user32.lib >> link.rsp
echo gdi32.lib >> link.rsp
echo advapi32.lib >> link.rsp
echo shell32.lib >> link.rsp
echo ole32.lib >> link.rsp

echo Response file created with:
type link.rsp

echo.
echo [LINK] Linking...

"%LINK%" @link.rsp /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain /LIBPATH:"%LIB_PATH%" /LIBPATH:"%WINSDK_PATH%\Lib\%WINSDK_VER%\um\x64" /LIBPATH:"%WINSDK_PATH%\Lib\%WINSDK_VER%\ucrt\x64" /OUT:"%OUT_DIR%\RawrXD_Full.dll" /PDB:"%OUT_DIR%\RawrXD_Full.pdb" /SUBSYSTEM:WINDOWS /MACHINE:X64 /LARGEADDRESSAWARE

echo Exit code: %ERRORLEVEL%

if exist "%OUT_DIR%\RawrXD_Full.dll" (
    echo [SUCCESS] Built: %OUT_DIR%\RawrXD_Full.dll
    for %%F in ("%OUT_DIR%\RawrXD_Full.dll") do echo [SIZE] %%~zF bytes
) else (
    echo [ERROR] DLL not created
)

REM Cleanup
del link.rsp 2>nul

endlocal
