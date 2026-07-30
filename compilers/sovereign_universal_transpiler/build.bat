@echo off
REM build.bat - Bootstrap build for Sovereign Universal Transpiler
REM Assembles all MASM modules and links into sut.exe

set MASM=ml64.exe
set LINK=link.exe
set OUTDIR=build

echo ============================================
echo   Sovereign Universal Transpiler v0.1
echo   Bootstrap Build
echo ============================================
echo.

REM Create output directory
if not exist %OUTDIR% mkdir %OUTDIR%

echo [1/4] Assembling kernel modules...
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\uir.obj          kernel\uir.asm
if errorlevel 1 goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\token.obj        kernel\token.asm
if errorlevel 1 goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\lexer.obj        kernel\lexer.asm
if errorlevel 1 goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\optimizer.obj    kernel\optimizer.asm
if errorlevel 1 goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\emitter_x64.obj  kernel\emitter_x64.asm
if errorlevel 1 goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\pe_writer.obj    kernel\pe_writer.asm
if errorlevel 1 goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\diagnostics.obj  kernel\diagnostics.asm
if errorlevel 1 goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\utils.obj        kernel\utils.asm
if errorlevel 1 goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\compiler.obj     kernel\compiler.asm
if errorlevel 1 goto :error

echo [2/4] Assembling frontend adapters...
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\frontend_api.obj  frontends\frontend_api.asm
if errorlevel 1 goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\php_adapter.obj   frontends\php_adapter.asm
if errorlevel 1 goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\c_adapter.obj     frontends\c_adapter.asm
if errorlevel 1 goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\python_adapter.obj frontends\python_adapter.asm
if errorlevel 1 goto :error

echo [3/4] Assembling runtime...
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\runtime.obj       runtime\runtime.asm
if errorlevel 1 goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\print.obj         runtime\print.asm
if errorlevel 1 goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\exit.obj          runtime\exit.asm
if errorlevel 1 goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\memory.obj        runtime\memory.asm
if errorlevel 1 goto :error

echo [4/4] Linking sut.exe...
%LINK% /nologo /SUBSYSTEM:CONSOLE /ENTRY:main ^
    /OUT:%OUTDIR%\sut.exe ^
    %OUTDIR%\compiler.obj ^
    %OUTDIR%\uir.obj ^
    %OUTDIR%\token.obj ^
    %OUTDIR%\lexer.obj ^
    %OUTDIR%\optimizer.obj ^
    %OUTDIR%\emitter_x64.obj ^
    %OUTDIR%\pe_writer.obj ^
    %OUTDIR%\diagnostics.obj ^
    %OUTDIR%\utils.obj ^
    %OUTDIR%\frontend_api.obj ^
    %OUTDIR%\php_adapter.obj ^
    %OUTDIR%\c_adapter.obj ^
    %OUTDIR%\python_adapter.obj ^
    %OUTDIR%\runtime.obj ^
    %OUTDIR%\print.obj ^
    %OUTDIR%\exit.obj ^
    %OUTDIR%\memory.obj ^
    kernel32.lib

if errorlevel 1 goto :error

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