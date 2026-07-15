@echo off
setlocal enabledelayedexpansion

echo [LINK] RawrXD Full Build - Local Linker
echo =======================================

set "BUILD_DIR=d:\rawrxd\build-master"
set "OUT_DIR=%BUILD_DIR%\bin"
set "DEBUG_PIPE=d:\rawrxd\build-debug-pipeline"

echo [1/3] Copying runtime DLLs to build-master...
xcopy /Y "%DEBUG_PIPE%\*.dll" "%BUILD_DIR%\" >nul 2>&1

echo [2/3] Creating response file...
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

echo [3/3] Linking with local linker...
"%DEBUG_PIPE%\link.exe" @link.rsp /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain /LIBPATH:"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\lib\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" /OUT:"%OUT_DIR%\RawrXD_Full.dll" /PDB:"%OUT_DIR%\RawrXD_Full.pdb" /SUBSYSTEM:WINDOWS /MACHINE:X64 /LARGEADDRESSAWARE

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
