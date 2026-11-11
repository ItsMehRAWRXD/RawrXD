@echo off
cd /d "%~dp0"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "OUTDIR=build"

set "OBJLIST=%OUTDIR%\compiler.obj %OUTDIR%\uir.obj %OUTDIR%\token.obj %OUTDIR%\lexer.obj %OUTDIR%\optimizer.obj %OUTDIR%\emitter_x64.obj %OUTDIR%\pe_writer.obj %OUTDIR%\diagnostics.obj %OUTDIR%\utils.obj %OUTDIR%\frontend_api.obj %OUTDIR%\php_adapter.obj %OUTDIR%\c_adapter.obj %OUTDIR%\python_adapter.obj %OUTDIR%\runtime.obj %OUTDIR%\print.obj %OUTDIR%\exit.obj %OUTDIR%\memory.obj"
set "KERNLIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"

echo Linking with the following objects:
echo %OBJLIST%
echo.
echo And library: %KERNLIB%
echo.

%LINK% /nologo /SUBSYSTEM:CONSOLE /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:%OUTDIR%\sut.exe %OBJLIST% "%KERNLIB%"

echo.
echo Link completed with exit code: %ERRORLEVEL%
pause
