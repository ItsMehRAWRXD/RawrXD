@echo off
REM build_fixed.bat - Fixed bootstrap build for Sovereign Universal Transpiler

cd /d "%~dp0"

set "MASM=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "OUTDIR=build"

echo ============================================
echo   Sovereign Universal Transpiler v0.1
echo   Bootstrap Build (Fixed)
echo ============================================
echo.

if not exist %OUTDIR% mkdir %OUTDIR%

echo [1/4] Assembling kernel modules...
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\uir.obj          kernel\uir.asm || goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\token.obj        kernel\token.asm || goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\lexer.obj        kernel\lexer.asm || goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\optimizer.obj    kernel\optimizer.asm || goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\emitter_x64.obj  kernel\emitter_x64.asm || goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\pe_writer.obj    kernel\pe_writer.asm || goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\diagnostics.obj  kernel\diagnostics.asm || goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\utils.obj        kernel\utils.asm || goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\compiler.obj     kernel\compiler.asm || goto :error

echo [2/4] Assembling frontend adapters...
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\frontend_api.obj  frontends\frontend_api.asm || goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\php_adapter.obj   frontends\php_adapter.asm || goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\c_adapter.obj     frontends\c_adapter.asm || goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\python_adapter.obj frontends\python_adapter.asm || goto :error

echo [3/4] Assembling runtime...
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\runtime.obj       runtime\runtime.asm || goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\print.obj         runtime\print.asm || goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\exit.obj          runtime\exit.asm || goto :error
%MASM% /c /nologo /W3 /Zi /Fo%OUTDIR%\memory.obj        runtime\memory.asm || goto :error

echo [4/4] Linking sut.exe...
%LINK% /nologo /SUBSYSTEM:CONSOLE /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:%OUTDIR%\sut.exe %OUTDIR%\compiler.obj %OUTDIR%\uir.obj %OUTDIR%\token.obj %OUTDIR%\lexer.obj %OUTDIR%\optimizer.obj %OUTDIR%\emitter_x64.obj %OUTDIR%\pe_writer.obj %OUTDIR%\diagnostics.obj %OUTDIR%\utils.obj %OUTDIR%\frontend_api.obj %OUTDIR%\php_adapter.obj %OUTDIR%\c_adapter.obj %OUTDIR%\python_adapter.obj %OUTDIR%\runtime.obj %OUTDIR%\print.obj %OUTDIR%\exit.obj %OUTDIR%\memory.obj "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib" || goto :error

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
