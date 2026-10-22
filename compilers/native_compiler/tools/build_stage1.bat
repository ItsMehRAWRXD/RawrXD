@echo off
REM ============================================================================
REM  rawr - stage1 build: compiler frontend, COFF object writer, and the
REM  C01-C08 certification suites.
REM ============================================================================
setlocal enabledelayedexpansion

for %%I in ("%~dp0..") do set "ROOT=%%~fI"
set "OUT=%~1"
if "%OUT%"=="" for %%I in ("%ROOT%\..\build\rawr_stage1") do set "OUT=%%~fI"

set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
call "%VCVARS%" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] failed to initialise MSVC environment
    exit /b 1
)
if not exist "%OUT%" mkdir "%OUT%" 2>nul

REM A certification run must never link an object from an earlier run. The
REM objects and the executables in the output directory are removed first, so
REM everything the suite uses is produced by this build.
del /q "%OUT%\*.obj" 2>nul
del /q "%OUT%\*.exe" 2>nul

echo === RawrXD Native Compiler - stage1 ===
echo output: %OUT%
echo.

echo [1/6] rawrstd...
cl /nologo /c /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /Fo:"%OUT%\\" ^
   "%ROOT%\rawrstd\src\sys.cpp" "%ROOT%\rawrstd\src\string.cpp" ^
   "%ROOT%\rawrstd\src\sha256.cpp" 2>&1
if errorlevel 1 ( echo [FAIL] rawrstd & exit /b 1 )
echo   [OK]

echo [2/6] compiler core...
cl /nologo /c /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" /Fo:"%OUT%\\" ^
   "%ROOT%\src\common\SourceManager.cpp" ^
   "%ROOT%\src\common\Diagnostics.cpp" ^
   "%ROOT%\src\frontend\Token.cpp" ^
   "%ROOT%\src\frontend\Lexer.cpp" ^
   "%ROOT%\src\frontend\Preprocessor.cpp" 2>&1
if errorlevel 1 ( echo [FAIL] compiler core & exit /b 1 )
echo   [OK]

echo [3/6] COFF object writer...
cl /nologo /c /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" /Fo:"%OUT%\\" ^
   "%ROOT%\src\object\CoffWriter.cpp" 2>&1
cl /nologo /c /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" /Fo:"%OUT%\\" ^
   "%ROOT%\src\asm\X64Assembler.cpp" 2>&1
if errorlevel 1 ( echo [FAIL] coff writer & exit /b 1 )
echo   [OK]

echo [4/6] building certification suites...
set "COMMON_OBJS=%OUT%\sys.obj %OUT%\string.obj %OUT%\sha256.obj"

cl /nologo /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" /Fo:"%OUT%\\" ^
   /Fe:"%OUT%\c01_lexer_test.exe" ^
   "%ROOT%\tests\c01_lexer_test.cpp" ^
   "%OUT%\sys.obj" "%OUT%\string.obj" ^
   "%OUT%\SourceManager.obj" "%OUT%\Diagnostics.obj" ^
   "%OUT%\Token.obj" "%OUT%\Lexer.obj" 2>&1
if errorlevel 1 ( echo [FAIL] C01 build & exit /b 1 )

cl /nologo /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" /Fo:"%OUT%\\" ^
   /Fe:"%OUT%\c02_coff_test.exe" ^
   "%ROOT%\tests\c02_coff_writer_test.cpp" ^
   %COMMON_OBJS% "%OUT%\CoffWriter.obj" 2>&1
if errorlevel 1 ( echo [FAIL] C02 build & exit /b 1 )

cl /nologo /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" /Fo:"%OUT%\\" ^
   /Fe:"%OUT%\c03_e2e_test.exe" ^
   "%ROOT%\tests\c03_e2e_test.cpp" ^
   %COMMON_OBJS% "%OUT%\CoffWriter.obj" 2>&1
if errorlevel 1 ( echo [FAIL] C03 build & exit /b 1 )

cl /nologo /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" /Fo:"%OUT%\\" ^
   /Fe:"%OUT%\c04_multi_test.exe" ^
   "%ROOT%\tests\c04_multi_object_test.cpp" ^
   %COMMON_OBJS% "%OUT%\CoffWriter.obj" 2>&1
if errorlevel 1 ( echo [FAIL] C04 build & exit /b 1 )

cl /nologo /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" /Fo:"%OUT%\\" ^
   /Fe:"%OUT%\c05_reloc_test.exe" ^
   "%ROOT%\tests\c05_reloc_import_test.cpp" ^
   %COMMON_OBJS% "%OUT%\CoffWriter.obj" 2>&1
if errorlevel 1 ( echo [FAIL] C05 build & exit /b 1 )

cl /nologo /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" /Fo:"%OUT%\\" ^
   /Fe:"%OUT%\c06_dll_test.exe" ^
   "%ROOT%\tests\c06_dll_test.cpp" ^
   %COMMON_OBJS% "%OUT%\CoffWriter.obj" 2>&1
if errorlevel 1 ( echo [FAIL] C06 build & exit /b 1 )

cl /nologo /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" /Fo:"%OUT%\\" ^
   /Fe:"%OUT%\c07_e2e_test.exe" ^
   "%ROOT%\tests\c07_e2e_test.cpp" ^
   %COMMON_OBJS% "%OUT%\CoffWriter.obj" "%OUT%\X64Assembler.obj" 2>&1
if errorlevel 1 ( echo [FAIL] C07 build & exit /b 1 )

cl /nologo /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" /Fo:"%OUT%\\" ^
   /Fe:"%OUT%\c08_negative_test.exe" ^
   "%ROOT%\tests\c08_negative_test.cpp" ^
   %COMMON_OBJS% "%OUT%\CoffWriter.obj" 2>&1
if errorlevel 1 ( echo [FAIL] C08 build & exit /b 1 )

cl /nologo /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" /Fo:"%OUT%\\" ^
   /Fe:"%OUT%\c09_provenance_test.exe" ^
   "%ROOT%\tests\c09_provenance_test.cpp" ^
   %COMMON_OBJS% 2>&1
if errorlevel 1 ( echo [FAIL] C09 build & exit /b 1 )
echo   [OK]

cl /nologo /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" /Fo:"%OUT%\\" ^
   /Fe:"%OUT%\c10_preprocessor_test.exe" ^
   "%ROOT%\tests\c10_preprocessor_test.cpp" ^
   %COMMON_OBJS% "%OUT%\SourceManager.obj" "%OUT%\Diagnostics.obj" ^
   "%OUT%\Token.obj" "%OUT%\Lexer.obj" "%OUT%\Preprocessor.obj" 2>&1
if errorlevel 1 ( echo [FAIL] C10 build & exit /b 1 )
echo   [OK]
echo [5/6] running certification suites...
echo.
"%OUT%\c01_lexer_test.exe"
if errorlevel 1 ( echo [FAIL] C01 & exit /b 1 )
echo.
"%OUT%\c02_coff_test.exe" "%OUT%"
if errorlevel 1 ( echo [FAIL] C02 & exit /b 1 )
echo.

echo [6/6] running the toolchain suites...
REM The linker is the first-party RawrXD native linker. RAWR_LINKER overrides
REM the location, so a build from an exported tree can point at a linker built
REM from the exported source. The default is unchanged.
if "%RAWR_LINKER%"=="" set "LINKER=F:\rawrxd\_pre_merge_backup\toolchain\from_scratch\phase2_linker\build\rawrxd_link.exe"
if not "%RAWR_LINKER%"=="" set "LINKER=%RAWR_LINKER%"
if not exist "%LINKER%" (
    echo   [SKIP] the RawrXD linker was not found at "%LINKER%"
    echo.
    echo RAWR_NATIVE_COMPILER_STAGE1 = PASS
    exit /b 0
)

"%OUT%\c03_e2e_test.exe" "%OUT%" "%LINKER%"
if errorlevel 1 ( echo [FAIL] C03 & exit /b 1 )
echo.
"%OUT%\c04_multi_test.exe" "%OUT%" "%LINKER%"
if errorlevel 1 ( echo [FAIL] C04 & exit /b 1 )
echo.
"%OUT%\c05_reloc_test.exe" "%OUT%" "%LINKER%"
if errorlevel 1 ( echo [FAIL] C05 & exit /b 1 )
echo.
"%OUT%\c06_dll_test.exe" "%OUT%" "%LINKER%"
if errorlevel 1 ( echo [FAIL] C06 & exit /b 1 )
echo.
"%OUT%\c08_negative_test.exe" "%OUT%" "%LINKER%"
if errorlevel 1 ( echo [FAIL] C08 & exit /b 1 )
echo.
"%OUT%\c07_e2e_test.exe" "%OUT%" "%LINKER%"
if errorlevel 1 ( echo [FAIL] C07 & exit /b 1 )
echo.

"%OUT%\c10_preprocessor_test.exe" "%OUT%"

if errorlevel 1 ( echo [FAIL] C10 & exit /b 1 )
echo.

REM The provenance gate runs last, so it inspects the objects this build
REM produced rather than the ones a previous build left behind.
"%OUT%\c09_provenance_test.exe" "%OUT%" "%ROOT%"
if errorlevel 1 ( echo [FAIL] C09 & exit /b 1 )

echo.
echo RAWR_NATIVE_COMPILER_STAGE1 = PASS
exit /b 0
