@echo off
REM Build the Stage 2 tools: the C front end and the assembler driver.
REM The same flags as build_stage1.bat.
setlocal enabledelayedexpansion
for %%I in ("%~dp0..") do set "ROOT=%%~fI"
set "OUT=%~1"
if "%OUT%"=="" for %%I in ("%ROOT%\..\build\rawr_stage1") do set "OUT=%%~fI"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 ( echo [ERROR] failed to initialise MSVC environment & exit /b 1 )
if not exist "%OUT%" mkdir "%OUT%" 2>nul
set "COMMON_OBJS=%OUT%\sys.obj %OUT%\string.obj %OUT%\sha256.obj"

echo === Stage 2: the C front end and the assembler driver ===
cl /nologo /c /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /Fo:"%OUT%\\" ^
   "%ROOT%\rawrstd\src\sys.cpp" "%ROOT%\rawrstd\src\string.cpp" ^
   "%ROOT%\rawrstd\src\sha256.cpp" 2>&1
if errorlevel 1 ( echo [FAIL] rawrstd & exit /b 1 )

cl /nologo /c /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" /Fo:"%OUT%\\" ^
   "%ROOT%\src\common\SourceManager.cpp" ^
   "%ROOT%\src\common\Diagnostics.cpp" ^
   "%ROOT%\src\frontend\Token.cpp" ^
   "%ROOT%\src\frontend\Lexer.cpp" 2>&1
if errorlevel 1 ( echo [FAIL] frontend core & exit /b 1 )

cl /nologo /c /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" /Fo:"%OUT%\\" ^
   "%ROOT%\src\frontend\c_stage2.cpp" 2>&1
if errorlevel 1 ( echo [FAIL] the C front end & exit /b 1 )

cl /nologo /c /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" /Fo:"%OUT%\\" ^
   "%ROOT%\src\object\CoffWriter.cpp" "%ROOT%\src\asm\X64Assembler.cpp" 2>&1
if errorlevel 1 ( echo [FAIL] the assembler & exit /b 1 )

cl /nologo /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" ^
   /Fe:"%OUT%\rawr_c.exe" ^
   "%ROOT%\tools\rawr_c.cpp" ^
   %COMMON_OBJS% "%OUT%\SourceManager.obj" "%OUT%\Token.obj" "%OUT%\Lexer.obj" ^
   "%OUT%\c_stage2.obj" "%OUT%\Diagnostics.obj" 2>&1
if errorlevel 1 ( echo [FAIL] rawr_c & exit /b 1 )

cl /nologo /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" ^
   /Fe:"%OUT%\rawr_asm.exe" ^
   "%ROOT%\tools\rawr_asm.cpp" ^
   %COMMON_OBJS% "%OUT%\CoffWriter.obj" "%OUT%\X64Assembler.obj" 2>&1
if errorlevel 1 ( echo [FAIL] rawr_asm & exit /b 1 )

cl /nologo /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" ^
   /Fe:"%OUT%\s2_pipeline_test.exe" ^
   "%ROOT%\tests\s2_pipeline_test.cpp" ^
   %COMMON_OBJS% 2>&1
if errorlevel 1 ( echo [FAIL] s2_pipeline_test & exit /b 1 )

if not exist "%OUT%\s2_ws" mkdir "%OUT%\s2_ws" 2>nul

echo   [OK]
exit /b 0
