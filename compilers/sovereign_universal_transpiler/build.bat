@echo off
REM build.bat - Bootstrap build for Sovereign Universal Transpiler
REM Assembles all MASM modules and links into sut.exe

REM Change to the project root directory
cd /d d:\rawrxd\compilers\sovereign_universal_transpiler

set "OUTDIR=build"

echo ============================================
echo   Sovereign Universal Transpiler v0.1
echo   Bootstrap Build
echo ============================================
echo.

REM Create output directory
if not exist %OUTDIR% mkdir %OUTDIR%

echo [1/4] Assembling kernel modules...
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe /c /nologo /W3 /Zi /Fo%OUTDIR%\uir.obj          kernel\uir.asm
if errorlevel 1 goto :error
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe /c /nologo /W3 /Zi /Fo%OUTDIR%\token.obj        kernel\token.asm
if errorlevel 1 goto :error
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe /c /nologo /W3 /Zi /Fo%OUTDIR%\lexer.obj        kernel\lexer.asm
if errorlevel 1 goto :error
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe /c /nologo /W3 /Zi /Fo%OUTDIR%\optimizer.obj    kernel\optimizer.asm
if errorlevel 1 goto :error
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe /c /nologo /W3 /Zi /Fo%OUTDIR%\emitter_x64.obj  kernel\emitter_x64.asm
if errorlevel 1 goto :error
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe /c /nologo /W3 /Zi /Fo%OUTDIR%\pe_writer.obj    kernel\pe_writer.asm
if errorlevel 1 goto :error
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe /c /nologo /W3 /Zi /Fo%OUTDIR%\diagnostics.obj  kernel\diagnostics.asm
if errorlevel 1 goto :error
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe /c /nologo /W3 /Zi /Fo%OUTDIR%\utils.obj        kernel\utils.asm
if errorlevel 1 goto :error
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe /c /nologo /W3 /Zi /Fo%OUTDIR%\compiler.obj     kernel\compiler.asm
if errorlevel 1 goto :error

echo [2/4] Assembling frontend adapters...
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe /c /nologo /W3 /Zi /Fo%OUTDIR%\frontend_api.obj  frontends\frontend_api.asm
if errorlevel 1 goto :error
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe /c /nologo /W3 /Zi /Fo%OUTDIR%\php_adapter.obj   frontends\php_adapter.asm
if errorlevel 1 goto :error
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe /c /nologo /W3 /Zi /Fo%OUTDIR%\c_adapter.obj     frontends\c_adapter.asm
if errorlevel 1 goto :error
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe /c /nologo /W3 /Zi /Fo%OUTDIR%\python_adapter.obj frontends\python_adapter.asm
if errorlevel 1 goto :error

echo [3/4] Assembling runtime...
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe /c /nologo /W3 /Zi /Fo%OUTDIR%\runtime.obj       runtime\runtime.asm
if errorlevel 1 goto :error
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe /c /nologo /W3 /Zi /Fo%OUTDIR%\print.obj         runtime\print.asm
if errorlevel 1 goto :error
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe /c /nologo /W3 /Zi /Fo%OUTDIR%\exit.obj          runtime\exit.asm
if errorlevel 1 goto :error
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe /c /nologo /W3 /Zi /Fo%OUTDIR%\memory.obj        runtime\memory.asm
if errorlevel 1 goto :error

echo [4/4] Linking sut.exe...
C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe /nologo /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /LARGEADDRESSAWARE:NO /OUT:%OUTDIR%\sut.exe %OUTDIR%\compiler.obj %OUTDIR%\uir.obj %OUTDIR%\token.obj %OUTDIR%\lexer.obj %OUTDIR%\optimizer.obj %OUTDIR%\emitter_x64.obj %OUTDIR%\pe_writer.obj %OUTDIR%\diagnostics.obj %OUTDIR%\utils.obj %OUTDIR%\frontend_api.obj %OUTDIR%\php_adapter.obj %OUTDIR%\c_adapter.obj %OUTDIR%\python_adapter.obj %OUTDIR%\runtime.obj %OUTDIR%\print.obj %OUTDIR%\exit.obj %OUTDIR%\memory.obj C:\PROGRA~2\WI3CF2~1\10\Lib\100226~1.0\um\x64\kernel32.lib
if errorlevel 1 goto :error

REM Validate PE was created
if not exist %OUTDIR%\sut.exe goto :error

echo.
echo ============================================
echo   BUILD COMPLETE
echo   Output: %OUTDIR%\sut.exe
echo ============================================
echo.
echo Usage: sut.exe ^<input^> ^<output.exe^>
echo.
goto :eof

:error
echo.
echo ============================================
echo   BUILD FAILED
echo ============================================
exit /b 1