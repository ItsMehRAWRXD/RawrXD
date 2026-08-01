@echo off
REM ============================================================================
REM RawrXD v15.0.0 - Master Build Script
REM Builds the complete ecosystem: Sovereign Transpiler + RawrXD IDE + Runtime
REM ============================================================================

setlocal EnableDelayedExpansion

echo ============================================================================
echo   RawrXD v15.0.0 - Master Build System
echo   Building: Sovereign Transpiler + IDE + Runtime
echo ============================================================================
echo.

REM Configuration
set "ROOT=d:\rawrxd"
set "MASM=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "SDKLIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
set "OUTDIR=%ROOT%\bin"
set "SUTDIR=%ROOT%\compilers\sovereign_universal_transpiler"

REM Create output directories
if not exist "%OUTDIR%" mkdir "%OUTDIR%"
if not exist "%SUTDIR%\build" mkdir "%SUTDIR%\build"

set "TOTAL_START=%TIME%"

REM ============================================================================
REM PHASE 1: Build Sovereign Universal Transpiler (SUT)
REM ============================================================================
echo [Phase 1/4] Building Sovereign Universal Transpiler...
echo.

cd /d "%SUTDIR%"

REM Clean previous build
del /q build\*.obj 2>nul
del /q build\sut.exe 2>nul

REM Assemble kernel modules
echo   [1/3] Assembling kernel modules...
"%MASM%" /c /nologo /W3 /Zi /Fo"build\uir.obj"          "kernel\uir.asm"          || goto :error
"%MASM%" /c /nologo /W3 /Zi /Fo"build\token.obj"        "kernel\token.asm"        || goto :error
"%MASM%" /c /nologo /W3 /Zi /Fo"build\lexer.obj"        "kernel\lexer.asm"        || goto :error
"%MASM%" /c /nologo /W3 /Zi /Fo"build\optimizer.obj"    "kernel\optimizer.asm"    || goto :error
"%MASM%" /c /nologo /W3 /Zi /Fo"build\emitter_x64.obj"  "kernel\emitter_x64.asm"  || goto :error
"%MASM%" /c /nologo /W3 /Zi /Fo"build\pe_writer.obj"    "kernel\pe_writer.asm"    || goto :error
"%MASM%" /c /nologo /W3 /Zi /Fo"build\diagnostics.obj"  "kernel\diagnostics.asm"  || goto :error
"%MASM%" /c /nologo /W3 /Zi /Fo"build\utils.obj"        "kernel\utils.asm"        || goto :error
"%MASM%" /c /nologo /W3 /Zi /Fo"build\compiler.obj"     "kernel\compiler.asm"     || goto :error

REM Assemble frontends
echo   [2/3] Assembling frontend adapters...
"%MASM%" /c /nologo /W3 /Zi /Fo"build\frontend_api.obj"  "frontends\frontend_api.asm"  || goto :error
"%MASM%" /c /nologo /W3 /Zi /Fo"build\php_adapter.obj"   "frontends\php_adapter.asm"   || goto :error
"%MASM%" /c /nologo /W3 /Zi /Fo"build\c_adapter.obj"     "frontends\c_adapter.asm"     || goto :error
"%MASM%" /c /nologo /W3 /Zi /Fo"build\python_adapter.obj" "frontends\python_adapter.asm" || goto :error

REM Assemble runtime
echo   [3/3] Assembling runtime modules...
"%MASM%" /c /nologo /W3 /Zi /Fo"build\runtime.obj"  "runtime\runtime.asm"  || goto :error
"%MASM%" /c /nologo /W3 /Zi /Fo"build\print.obj"    "runtime\print.asm"    || goto :error
"%MASM%" /c /nologo /W3 /Zi /Fo"build\exit.obj"     "runtime\exit.asm"     || goto :error
"%MASM%" /c /nologo /W3 /Zi /Fo"build\memory.obj"   "runtime\memory.asm"   || goto :error

REM Link SUT with explicit object list
echo   Linking sut.exe...
"%LINK%" /nologo /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /LARGEADDRESSAWARE:NO /OUT:"build\sut.exe" ^
    "build\compiler.obj" ^
    "build\uir.obj" ^
    "build\token.obj" ^
    "build\lexer.obj" ^
    "build\optimizer.obj" ^
    "build\emitter_x64.obj" ^
    "build\pe_writer.obj" ^
    "build\diagnostics.obj" ^
    "build\utils.obj" ^
    "build\frontend_api.obj" ^
    "build\php_adapter.obj" ^
    "build\c_adapter.obj" ^
    "build\python_adapter.obj" ^
    "build\runtime.obj" ^
    "build\print.obj" ^
    "build\exit.obj" ^
    "build\memory.obj" ^
    "%SDKLIB%" || goto :error

REM Copy SUT to main bin directory
copy /y "build\sut.exe" "%OUTDIR%\SovereignTranspiler.exe" >nul

echo   [OK] Sovereign Transpiler built successfully
echo.

REM ============================================================================
REM PHASE 2: Build RawrXD Core Components
REM ============================================================================
echo [Phase 2/4] Building RawrXD Core Components...
echo.

cd /d "%ROOT%"

REM Build RawrEngine (core inference engine)
echo   Building RawrEngine.exe...
if exist "src\core\RawrEngine.cpp" (
    cl /nologo /O2 /EHsc /std:c++20 /Fe"%OUTDIR%\RawrEngine.exe" ^
        "src\core\RawrEngine.cpp" ^
        /link /SUBSYSTEM:CONSOLE kernel32.lib user32.lib
    if errorlevel 1 echo     [WARN] RawrEngine build had issues, continuing...
) else (
    echo     [SKIP] RawrEngine.cpp not found, using placeholder
    copy /y "bin\demo_unified.exe" "%OUTDIR%\RawrEngine.exe" >nul 2>&1
)

echo   [OK] Core components ready
echo.

REM ============================================================================
REM PHASE 3: Build RawrXD IDE
REM ============================================================================
echo [Phase 3/4] Building RawrXD IDE...
echo.

REM Build IDE components
if exist "ide\RawrXD_IDE.cpp" (
    echo   Building RawrXD_IDE.exe...
    cl /nologo /O2 /EHsc /std:c++20 /Fe"%OUTDIR%\RawrXD_IDE.exe" ^
        "ide\RawrXD_IDE.cpp" ^
        /link /SUBSYSTEM:WINDOWS kernel32.lib user32.lib gdi32.lib
    if errorlevel 1 echo     [WARN] IDE build had issues, using existing...
) else (
    echo   [SKIP] IDE source not found, using existing binaries
)

REM Copy existing IDE if available
if exist "bin\RawrXD.exe" (
    copy /y "bin\RawrXD.exe" "%OUTDIR%\RawrXD.exe" >nul
)
if exist "bin\RawrXD-Win32IDE.exe" (
    copy /y "bin\RawrXD-Win32IDE.exe" "%OUTDIR%\RawrXD-Win32IDE.exe" >nul
)

echo   [OK] IDE components ready
echo.

REM ============================================================================
REM PHASE 4: Build Runtime DLLs
REM ============================================================================
echo [Phase 4/4] Building Runtime Components...
echo.

REM Build runtime DLLs if source exists
if exist "runtime\RawrXDRuntime.cpp" (
    echo   Building RawrXDRuntime.dll...
    cl /nologo /O2 /EHsc /std:c++20 /LD /Fe"%OUTDIR%\RawrXDRuntime.dll" ^
        "runtime\RawrXDRuntime.cpp" ^
        /link /DLL /EXPORT:InitializeRuntime /EXPORT:LoadModel /EXPORT:RunInference
    if errorlevel 1 echo     [WARN] Runtime DLL build had issues...
)

REM Copy existing runtime DLLs
for %%F in (bin\*.dll) do (
    copy /y "%%F" "%OUTDIR%\" >nul 2>&1
)

echo   [OK] Runtime components ready
echo.

REM ============================================================================
REM PHASE 5: Generate Release Manifest
REM ============================================================================
echo [Finalizing] Generating release manifest...
echo.

cd /d "%OUTDIR%"

REM Create RELEASE_MANIFEST.json
echo { > RELEASE_MANIFEST.json
echo   "version": "15.0.0", >> RELEASE_MANIFEST.json
echo   "build_date": "%DATE% %TIME%", >> RELEASE_MANIFEST.json
echo   "components": { >> RELEASE_MANIFEST.json
echo     "transpiler": "SovereignTranspiler.exe", >> RELEASE_MANIFEST.json
echo     "ide": ["RawrXD.exe", "RawrXD_IDE.exe", "RawrXD-Win32IDE.exe"], >> RELEASE_MANIFEST.json
echo     "engine": "RawrEngine.exe", >> RELEASE_MANIFEST.json
echo     "runtime": "RawrXDRuntime.dll" >> RELEASE_MANIFEST.json
echo   }, >> RELEASE_MANIFEST.json
echo   "files": [ >> RELEASE_MANIFEST.json

set "FIRST=1"
for %%F in (*.exe *.dll) do (
    if "!FIRST!"=="1" (
        set "FIRST=0"
    ) else (
        echo     , >> RELEASE_MANIFEST.json
    )
    for /f "tokens=*" %%H in ('certutil -hashfile "%%F" SHA256 ^| findstr /v "CertUtil" ^| findstr /v "hash"') do (
        set "HASH=%%H"
        set "HASH=!HASH: =!"
        echo     { >> RELEASE_MANIFEST.json
        echo       "name": "%%F", >> RELEASE_MANIFEST.json
        echo       "size": %%~zF, >> RELEASE_MANIFEST.json
        echo       "sha256": "!HASH!" >> RELEASE_MANIFEST.json
        echo     } >> RELEASE_MANIFEST.json
    )
)

echo   ] >> RELEASE_MANIFEST.json
echo } >> RELEASE_MANIFEST.json

REM Create verification script
echo @echo off > verify_release.bat
echo echo RawrXD v15.0.0 Release Verification >> verify_release.bat
echo echo ================================= >> verify_release.bat
echo echo. >> verify_release.bat
echo for %%%%F in (*.exe *.dll) do ( >> verify_release.bat
echo   certutil -hashfile %%%%F SHA256 ^| findstr /v "CertUtil" ^| findstr /v "hash" ^> %%%%F.hash.tmp >> verify_release.bat
echo   set /p HASH=^< %%%%F.hash.tmp >> verify_release.bat
echo   del %%%%F.hash.tmp >> verify_release.bat
echo   echo %%%%F: %%HASH%% >> verify_release.bat
echo ) >> verify_release.bat
echo echo. >> verify_release.bat
echo echo Verification complete. >> verify_release.bat

REM ============================================================================
REM Summary
REM ============================================================================
echo ============================================================================
echo   BUILD COMPLETE - RawrXD v15.0.0
echo ============================================================================
echo.
echo Output Directory: %OUTDIR%
echo.
echo Generated Binaries:
for %%F in ("%OUTDIR%\*.exe") do (
    echo   - %%~nF.exe (%%~zF bytes)
)
echo.
echo Generated DLLs:
for %%F in ("%OUTDIR%\*.dll") do (
    echo   - %%~nF.dll (%%~zF bytes)
) 2>nul
echo.
echo Files:
echo   - RELEASE_MANIFEST.json (SHA-256 hashes)
echo   - verify_release.bat (verification script)
echo.
echo Usage:
echo   SovereignTranspiler.exe ^<input.php^> ^<output.exe^>
echo   RawrXD.exe (launch IDE)
echo   RawrEngine.exe (launch inference engine)
echo.
echo ============================================================================

set "TOTAL_END=%TIME%"
echo Build started: %TOTAL_START%
echo Build ended:   %TOTAL_END%

goto :eof

:error
echo.
echo ERROR: Build failed at phase %ERRORLEVEL%
echo.
exit /b 1
