@echo off
setlocal EnableDelayedExpansion

set ML64="C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe"
set CL="C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe"
set LINK="C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe"

set SRCDIR=d:\rawrxd\src\script
set BUILDDIR=d:\rawrxd\build-master

echo ╔══════════════════════════════════════════════════════════════════════════╗
echo ║  RawrXD Golden Master - Full Corpus Sealing                              ║
echo ╚══════════════════════════════════════════════════════════════════════════╝
echo.

REM Clean previous artifacts
echo [Cleanup] Removing old databases...
if exist %BUILDDIR%\rawrxd_golden_masters.db del %BUILDDIR%\rawrxd_golden_masters.db 2>nul
if exist %BUILDDIR%\rawrxd_golden_masters.json del %BUILDDIR%\rawrxd_golden_masters.json 2>nul
echo           Done.
echo.

REM Assemble the interpreter with trace collector
echo [Build 1/4] Assembling interpreter.asm...
%ML64% /c /W3 /nologo /Zi /D"RAWRXD_TRACE_COLLECTOR=1" /Fo:%BUILDDIR%\interpreter_seal.obj %SRCDIR%\masm\interpreter.asm >nul 2>&1
if errorlevel 1 (
    echo ERROR: Assembly failed
    exit /b 1
)
echo              OK

REM Compile golden_master.cpp
echo [Build 2/4] Compiling golden_master.cpp...
%CL% /c /std:c++20 /W3 /O2 /nologo /Fo:%BUILDDIR%\golden_master.obj %SRCDIR%\golden_master.cpp /I%SRCDIR% /I"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" >nul 2>&1
if errorlevel 1 (
    echo ERROR: golden_master.cpp compilation failed
    exit /b 1
)
echo              OK

REM Compile the sealing tool
echo [Build 3/4] Compiling seal_full_corpus.cpp...
%CL% /c /std:c++20 /W3 /O2 /nologo /Fo:%BUILDDIR%\seal_corpus.obj %SRCDIR%\seal_full_corpus.cpp /I%SRCDIR% /I"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" >nul 2>&1
if errorlevel 1 (
    echo ERROR: Sealing tool compilation failed
    exit /b 1
)
echo              OK

REM Link the executable
echo [Build 4/4] Linking seal_corpus.exe...
%LINK% /nologo %BUILDDIR%\seal_corpus.obj %BUILDDIR%\golden_master.obj %BUILDDIR%\interpreter_seal.obj /out:%BUILDDIR%\seal_corpus.exe /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" /LIBPATH:"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\x64" kernel32.lib user32.lib /subsystem:console /machine:x64 >nul 2>&1
if errorlevel 1 (
    echo ERROR: Link failed
    exit /b 1
)
echo              OK
echo.

REM Run the sealing process
echo ╔══════════════════════════════════════════════════════════════════════════╗
echo ║  EXECUTING SEALING PROCESS                                                 ║
echo ╚══════════════════════════════════════════════════════════════════════════╝
echo.

%BUILDDIR%\seal_corpus.exe
set RESULT=%errorlevel%

echo.
echo ╔══════════════════════════════════════════════════════════════════════════╗
if %RESULT%==0 (
    echo ║  ✓ SEALING SUCCESSFUL                                                      ║
) else (
    echo ║  ✗ SEALING FAILED                                                          ║
)
echo ╚══════════════════════════════════════════════════════════════════════════╝
echo.

REM Display output files
if exist %BUILDDIR%\rawrxd_golden_masters.db (
    for %%F in (%BUILDDIR%\rawrxd_golden_masters.db) do (
        echo Database:  %%~zF bytes
    )
)
if exist %BUILDDIR%\rawrxd_golden_masters.json (
    for %%F in (%BUILDDIR%\rawrxd_golden_masters.json) do (
        echo JSON:      %%~zF bytes
    )
)

echo.
echo Files created in: %BUILDDIR%
echo.

exit /b %RESULT%
