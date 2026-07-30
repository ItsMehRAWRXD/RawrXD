@echo off
REM Build Sovereign Compiler Engine
@echo off
setlocal

REM Find VS2022
set "VSPATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise"
if not exist "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" (
    set "VSPATH=C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
)
if not exist "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" (
    set "VSPATH=C:\Program Files\Microsoft Visual Studio\2022\Community"
)

if not exist "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" (
    echo ERROR: Visual Studio 2022 not found
    exit /b 1
)

echo Found VS2022 at: %VSPATH%

REM Call vcvarsall
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

cd /d "d:\rawrxd\compilers\sovereign_engine"

echo.
echo Building Sovereign Compiler Engine...
echo.

REM Assemble core components
ml64.exe /nologo /c /Fo:core\sovereign_compiler_base.obj core\sovereign_compiler_base.asm
ml64.exe /nologo /c /Fo:core\pe_writer.obj core\pe_writer.asm

REM Assemble PHP frontend
ml64.exe /nologo /c /Fo:frontends\php_frontend.obj frontends\php_frontend.asm

REM Link into engine DLL
link.exe /nologo /dll /out:SovereignCompilerEngine.dll ^
    core\sovereign_compiler_base.obj ^
    core\pe_writer.obj ^
    frontends\php_frontend.obj ^
    kernel32.lib

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo BUILD FAILED
    exit /b %ERRORLEVEL%
)

echo.
echo ==========================================
echo BUILD SUCCESSFUL
echo ==========================================
dir SovereignCompilerEngine.dll
echo.
echo Next steps:
echo   - Test with: hello.php
echo   - Build other frontends
echo ==========================================
