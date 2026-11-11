@echo off
setlocal EnableExtensions
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 2
set "EV=F:\rawrxd\evidence\RAWRXD_SOVEREIGN_PE_RUNTIME_001"
set "LINK=F:\rawrxd\build_5os_win\rawrxd_link.exe"
set "SRC=F:\rawrxd\tests\sovereign_linker\test_minimal.c"
set "OBJ=%EV%\test_minimal.obj"
set "EXE=%EV%\test_exit42.exe"
set "LOG=%EV%\runtime_log.txt"

echo === LINKER SHA256 === > "%LOG%"
certutil -hashfile "%LINK%" SHA256 >> "%LOG%"

echo === COMPILE test_minimal.c === >> "%LOG%"
cl /nologo /c /O2 /Fo"%OBJ%" "%SRC%" >> "%LOG%" 2>&1
if errorlevel 1 (echo COMPILE_FAIL>> "%LOG%" & exit /b 3)

echo === LINK with rawrxd_link === >> "%LOG%"
"%LINK%" -o "%EXE%" -v "%OBJ%" >> "%LOG%" 2>&1
if errorlevel 1 (echo LINK_FAIL>> "%LOG%" & exit /b 4)

echo === DUMPBIN IMPORTS/HEADERS === >> "%LOG%"
dumpbin /HEADERS /IMPORTS "%EXE%" >> "%LOG%" 2>&1

echo === RUN === >> "%LOG%"
"%EXE%"
set "RC=%ERRORLEVEL%"
echo EXIT_CODE=%RC%>> "%LOG%"
echo EXIT_CODE=%RC%
if not "%RC%"=="42" (echo RUNTIME_FAIL_EXPECTED_42>> "%LOG%" & exit /b 5)
echo RUNTIME_PASS_EXIT_42>> "%LOG%"
exit /b 0
