@echo off
REM Rebuild and run ONLY the C07 suite, using the same flags as
REM native_compiler\tools\build_stage1.bat.
setlocal enabledelayedexpansion
for %%I in ("%~dp0..") do set "ROOT=%%~fI"
set "OUT=%~1"
if "%OUT%"=="" for %%I in ("%ROOT%\..\build\rawr_stage1") do set "OUT=%%~fI"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
set "COMMON_OBJS=%OUT%\sys.obj %OUT%\string.obj %OUT%\sha256.obj"
REM Rebuild the COFF writer and the assembler from source. Linking against a
REM prebuilt object silently keeps the old code, which is how a source fix
REM in the encoder can be tested and still appear to have no effect.
cl /nologo /c /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" /Fo:"%OUT%\\" ^
   "%ROOT%\src\object\CoffWriter.cpp" "%ROOT%\src\asm\X64Assembler.cpp" 2>&1
if errorlevel 1 ( echo [FAIL] C07 assembler build & exit /b 1 )
cl /nologo /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" ^
   /Fe:"%OUT%\c07_e2e_test.exe" ^
   "%ROOT%\tests\c07_e2e_test.cpp" ^
   %COMMON_OBJS% "%OUT%\CoffWriter.obj" "%OUT%\X64Assembler.obj" 2>&1
if errorlevel 1 ( echo [FAIL] C07 build & exit /b 1 )
echo [OK] C07 build
set "LINKER=F:\rawrxd\_pre_merge_backup\toolchain\from_scratch\phase2_linker\build\rawrxd_link.exe"
"%OUT%\c07_e2e_test.exe" "%OUT%" "%LINKER%"
echo C07 exit=%errorlevel%
exit /b %errorlevel%
