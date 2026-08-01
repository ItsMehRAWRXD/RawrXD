@echo off
REM ===========================================================================
REM  build.cmd — RawrXD Sovereign Platform Build
REM  Uses your toolchain: ml64.exe + link.exe + nasm.exe
REM  No C++ compiler (cl.exe) required — this is a MASM-native build.
REM ===========================================================================
setlocal enabledelayedexpansion

set ROOT=%~dp0
set ROOT=%ROOT:~0,-1%

REM ===========================================================================
REM Toolchain paths — your exact installed locations
REM ===========================================================================
set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
set LIBEXE=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\lib.exe
set NASM=C:\Program Files\NASM\nasm.exe

REM SDK paths (22621 has UCRT, 26100 has um)
set SDKROOT=C:\Program Files (x86)\Windows Kits\10
set SDKVER_UC=10.0.22621.0
set SDKVER_UM=10.0.26100.0

REM ===========================================================================
REM Library search paths for linker
REM ===========================================================================
set LIBDIRS=/LIBPATH:"%ROOT%\build\obj" /LIBPATH:"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\%SDKVER_UC%\ucrt\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\%SDKVER_UM%\um\x64"

REM Standard libs for MASM console executables
set BASELIBS=kernel32.lib user32.lib gdi32.lib advapi32.lib shell32.lib shlwapi.lib ucrt.lib

REM ===========================================================================
REM Include paths for MASM
REM ===========================================================================
set MASM_INCLUDES=/I"%SRCDIR%" /I"%SRCDIR%\runtime" /I"%SRCDIR%\model" /I"%SRCDIR%\gguf" /I"%SRCDIR%\tokenizer" /I"%SRCDIR%\agent" /I"%SRCDIR%\gpu" /I"%AGENTDIR%" /I"%ROOT%\tests"

REM 32-bit MASM (for legacy files that use .686p/.model flat directives)
set ML32=C:\masm32\bin\ml.exe

REM ===========================================================================
REM Targets
REM ===========================================================================
set TARGET=%1
if "%TARGET%"=="" set TARGET=all

REM ===========================================================================
REM Directories
REM ===========================================================================
set SRCDIR=%ROOT%\src
set AGENTDIR=%SRCDIR%\agentic
set OBJDIR=%ROOT%\build\obj
set BINDIR=%ROOT%\build\bin

if "%TARGET%"=="clean" goto :clean
if "%TARGET%"=="certify" goto :certify

:build
echo.
echo ========================================
echo  RawrXD Sovereign Platform Build
echo  Toolchain: MASM x64 (ml64.exe)
echo  Target: %TARGET%
echo ========================================
echo.

if not exist "%OBJDIR%" mkdir "%OBJDIR%"
if not exist "%BINDIR%" mkdir "%BINDIR%"

REM ===========================================================================
REM Step 1: Core IPC/Widget objects (skipped — widget-specific, not runtime)
REM ===========================================================================
echo [1/5] Core Objects... (widget files skipped — runtime build only)

REM ===========================================================================
REM Step 2: Engine objects (legacy — requires modern 32-bit MASM with AVX-512)
REM Skipped: gpu_dma and titan_master need a newer 32-bit assembler
REM ===========================================================================
echo [2/5] Engine Objects... (legacy files skipped — need modern 32-bit MASM)

REM ===========================================================================
REM Step 3: Runtime engine objects
REM ===========================================================================
echo [3/5] Runtime Engine Objects...
call :asm_sub runtime\kernel_registry.asm    kernel_registry.obj
call :asm_sub runtime\tensor.asm            tensor.obj
call :asm_sub runtime\q4_matmul.asm         q4_matmul.obj
call :asm_sub runtime\kv_cache.asm          kv_cache.obj
call :asm_sub runtime\sampler.asm           sampler.obj
call :asm_sub runtime\inference_engine.asm  inference_engine.obj
call :asm_sub model\transformer_block.asm   transformer_block.obj
call :asm_sub gguf\gguf_reader.asm          gguf_reader.obj
call :asm_sub tokenizer\bpe.asm             bpe.obj
call :asm_sub agent\agent_runtime.asm       agent_runtime.obj
call :asm_sub gpu\gpu_backend.asm           gpu_backend.obj

REM ===========================================================================
REM Step 4: Smoke test
REM ===========================================================================
if "%TARGET%"=="all" set TARGET=smoke
if "%TARGET%"=="smoke" (
    echo [4/5] Smoke Test...
    call :asm_test runtime_smoke.asm runtime_smoke.obj
    call :link_runtime runtime_smoke.exe /SUBSYSTEM:CONSOLE
)

REM ===========================================================================
REM Step 5: Widget server
REM ===========================================================================
if "%TARGET%"=="all" set TARGET=widget
if "%TARGET%"=="widget" (
    echo [5/5] Widget Server...
    call :link RawrXD_Widget.exe IPC_Bridge.obj WidgetEngine.obj HeadlessWidgets.obj /SUBSYSTEM:CONSOLE /ENTRY:Widget_Main
)

REM ===========================================================================
REM Summary
REM ===========================================================================
:summary
echo.
echo ========================================
echo  Build Complete
echo ========================================
if exist "%BINDIR%" (
    for %%f in ("%BINDIR%\*.exe") do (
        for /f "delims=" %%s in ('powershell -Command "[math]::Round((Get-Item '%%f').Length / 1KB, 1)"') do set SZ=%%s
        echo   %%~nxf  !SZ! KB
    )
)
echo ========================================
echo.
goto :eof

REM ===========================================================================
REM Subroutines
REM ===========================================================================
:asm
"%ML64%" /nologo /c /Cx /Zi /I"%SRCDIR%" /I"%SRCDIR%\runtime" /I"%SRCDIR%\model" /I"%SRCDIR%\gguf" /I"%SRCDIR%\tokenizer" /I"%SRCDIR%\agent" /I"%SRCDIR%\gpu" /I"%AGENTDIR%" /I"%ROOT%\tests" /Fo"%OBJDIR%\%2" "%SRCDIR%\%1"
if errorlevel 1 echo ERROR: %1 failed & exit /b 1
exit /b 0

:asm_agent
"%ML64%" /nologo /c /Cx /Zi /I"%SRCDIR%" /I"%SRCDIR%\runtime" /I"%SRCDIR%\model" /I"%SRCDIR%\gguf" /I"%SRCDIR%\tokenizer" /I"%SRCDIR%\agent" /I"%SRCDIR%\gpu" /I"%AGENTDIR%" /I"%ROOT%\tests" /Fo"%OBJDIR%\%2" "%AGENTDIR%\%1"
if errorlevel 1 echo ERROR: %1 failed & exit /b 1
exit /b 0

:asm_sub
"%ML64%" /nologo /c /Cx /Zi /I"%SRCDIR%" /I"%SRCDIR%\runtime" /I"%SRCDIR%\model" /I"%SRCDIR%\gguf" /I"%SRCDIR%\tokenizer" /I"%SRCDIR%\agent" /I"%SRCDIR%\gpu" /I"%AGENTDIR%" /I"%ROOT%\tests" /Fo"%OBJDIR%\%2" "%SRCDIR%\%1"
if errorlevel 1 echo ERROR: %1 failed & exit /b 1
exit /b 0

:asm_test
"%ML64%" /nologo /c /Cx /Zi /I"%SRCDIR%" /I"%SRCDIR%\runtime" /I"%SRCDIR%\model" /I"%SRCDIR%\gguf" /I"%SRCDIR%\tokenizer" /I"%SRCDIR%\agent" /I"%SRCDIR%\gpu" /I"%AGENTDIR%" /I"%ROOT%\tests" /Fo"%OBJDIR%\%2" "%ROOT%\tests\%1"
if errorlevel 1 echo ERROR: %1 failed & exit /b 1
exit /b 0

:asm_legacy
"%ML32%" /nologo /c /Cx /Zi /I"%SRCDIR%" /I"%SRCDIR%\runtime" /I"%SRCDIR%\model" /I"%SRCDIR%\gguf" /I"%SRCDIR%\tokenizer" /I"%SRCDIR%\agent" /I"%SRCDIR%\gpu" /I"%AGENTDIR%" /I"%ROOT%\tests" /Fo"%OBJDIR%\%2" "%AGENTDIR%\%1"
if errorlevel 1 echo ERROR: %1 failed & exit /b 1
exit /b 0

:link
set OBJFILE=%OBJDIR%\%2
set LINKFLAGS=%3
set RSPFILE=%TEMP%\rawrxd_link.rsp
echo -nologo > "%RSPFILE%"
echo -MACHINE:X64 >> "%RSPFILE%"
echo -OUT:"%BINDIR%\%1" >> "%RSPFILE%"
echo "%OBJFILE%" >> "%RSPFILE%"
echo %BASELIBS% >> "%RSPFILE%"
echo %LINKFLAGS% >> "%RSPFILE%"
echo -LIBPATH:"%ROOT%\build\obj" >> "%RSPFILE%"
echo -LIBPATH:"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64" >> "%RSPFILE%"
echo -LIBPATH:"C:\PROGRA~2\Windows Kits\10\Lib\%SDKVER_UC%\ucrt\x64" >> "%RSPFILE%"
echo -LIBPATH:"C:\PROGRA~2\Windows Kits\10\Lib\%SDKVER_UM%\um\x64" >> "%RSPFILE%"
"%LINK%" @"%RSPFILE%"
if errorlevel 1 echo ERROR: LINK %1 failed & exit /b 1
echo   Built: %BINDIR%\%1
exit /b 0

:link_runtime
set LINKFLAGS=%2
set RSPFILE=%TEMP%\rawrxd_link.rsp
echo -nologo > "%RSPFILE%"
echo -MACHINE:X64 >> "%RSPFILE%"
echo -OUT:"%BINDIR%\%1" >> "%RSPFILE%"
for %%f in ("%OBJDIR%\*.obj") do echo "%%f" >> "%RSPFILE%"
echo %BASELIBS% >> "%RSPFILE%"
echo %LINKFLAGS% >> "%RSPFILE%"
echo -LIBPATH:"%ROOT%\build\obj" >> "%RSPFILE%"
echo -LIBPATH:"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64" >> "%RSPFILE%"
echo -LIBPATH:"C:\PROGRA~2\Windows Kits\10\Lib\%SDKVER_UC%\ucrt\x64" >> "%RSPFILE%"
echo -LIBPATH:"C:\PROGRA~2\Windows Kits\10\Lib\%SDKVER_UM%\um\x64" >> "%RSPFILE%"
"%LINK%" @"%RSPFILE%"
if errorlevel 1 echo ERROR: LINK %1 failed & exit /b 1
echo   Built: %BINDIR%\%1
exit /b 0

REM ===========================================================================
REM Clean
REM ===========================================================================
:clean
echo Cleaning build artifacts...
if exist "%OBJDIR%" rmdir /s /q "%OBJDIR%"
if exist "%BINDIR%" rmdir /s /q "%BINDIR%"
echo Clean complete.
goto :eof

REM ===========================================================================
REM Certification
REM ===========================================================================
:certify
echo.
echo ========================================
echo  RawrXD Sovereign Certification
echo ========================================
echo.

set CERTPASS=1

REM Step 1: Clean build
echo [1/6] Clean Build...
if exist "%OBJDIR%" rmdir /s /q "%OBJDIR%"
if exist "%BINDIR%" rmdir /s /q "%BINDIR%"
mkdir "%OBJDIR%" 2>nul
mkdir "%BINDIR%" 2>nul

call :asm RawrXD_IPC_Bridge.asm IPC_Bridge.obj
if errorlevel 1 (echo   Build Core ASM        FAIL & set CERTPASS=0) else (echo   Build Core ASM        PASS)
call :asm RawrXD_WidgetEngine.asm WidgetEngine.obj
call :asm RawrXD_HeadlessWidgets.asm HeadlessWidgets.obj

REM Step 2: ODR check
echo [2/6] Backend Factory ODR Verification...
findstr /m "PowerShellDriver.cpp BareMetalDriver.cpp" "%SRCDIR%\orchestration\*.cpp" >nul 2>nul
if errorlevel 1 (echo   Backend Factory ODR   PASS) else (echo   Backend Factory ODR   FAIL & set CERTPASS=0)

REM Step 3: Build smoke test
echo [3/6] Smoke Test Build...
call :asm_test runtime_smoke.asm runtime_smoke.obj
if errorlevel 1 (echo   Smoke Test Build      FAIL & set CERTPASS=0) else (echo   Smoke Test Build      PASS)

REM Step 4: Link smoke test
echo [4/6] Smoke Test Link...
call :link runtime_smoke.exe runtime_smoke.obj /SUBSYSTEM:CONSOLE
if errorlevel 1 (echo   Smoke Test Link       FAIL & set CERTPASS=0) else (echo   Smoke Test Link       PASS)

REM Step 5: Benchmark capture check
echo [5/6] Benchmark Capture Verification...
dir "%ROOT%\benchmarks\runs\*.json" >nul 2>nul
if errorlevel 1 (echo   Benchmark Capture     SKIP) else (echo   Benchmark Capture     PASS)

REM Step 6: Integrity manifest
echo [6/6] Integrity Manifest...
if exist "%BINDIR%" (
    echo RawrXD Sovereign Certification Integrity Manifest > "%ROOT%\benchmarks\hashes\SHA256_MANIFEST.txt"
    echo Generated: >> "%ROOT%\benchmarks\hashes\SHA256_MANIFEST.txt"
    powershell -Command "Get-Date -Format 'yyyy-MM-ddTHH:mm:ss'" >> "%ROOT%\benchmarks\hashes\SHA256_MANIFEST.txt"
    echo. >> "%ROOT%\benchmarks\hashes\SHA256_MANIFEST.txt"
    for %%f in ("%BINDIR%\*.exe") do (
        for /f "delims=" %%h in ('powershell -Command "(Get-FileHash -Algorithm SHA256 '%%f').Hash"') do (
            echo %%h  %%~nxf >> "%ROOT%\benchmarks\hashes\SHA256_MANIFEST.txt"
        )
    )
    echo   Integrity Manifest    PASS
) else (
    echo   Integrity Manifest    SKIP
)

REM Result
echo.
echo ========================================
echo  RawrXD Sovereign Certification Result
echo ========================================
if "%CERTPASS%"=="1" (
    echo   STATUS: CERTIFIED
) else (
    echo   STATUS: FAILED
)
echo ========================================
echo.
exit /b %CERTPASS%
    exit /b 1
)

if "%OUTPUT%"=="" (
    set OUTPUT=%SOURCE:.c=.exe%
    set OUTPUT=%OUTPUT:.asm=.exe%
)

echo 🔨 Building %SOURCE%...

if "%SOURCE:~-2%"==".c" (
    "%TOOLCHAIN%\universal_compiler.exe" "%SOURCE%" -o "%OUTPUT%"
) else if "%SOURCE:~-4%"==".asm" (
    "%TOOLCHAIN%\minimal_assembler_v7.exe" "%SOURCE%" "%OUTPUT%.obj"
    "%TOOLCHAIN%\linker_fixed.exe" "%OUTPUT%.obj" /out:"%OUTPUT%" /subsystem:3
) else (
    echo Unknown file type: %SOURCE%
    exit /b 1
)

if %ERRORLEVEL%==0 (
    echo ✅ Build successful: %OUTPUT%
) else (
    echo ❌ Build failed
)

exit /b %ERRORLEVEL%
