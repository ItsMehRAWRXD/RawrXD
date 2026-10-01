@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 ( echo VCVARS_FAIL & exit /b 1 )
set S=%~dp0..\src\deep2
set O=%~dp0..\build_b3
if not exist "%O%" mkdir "%O%"
cl /nologo /EHsc /std:c++17 /O1 /MT /I "%S%" /I "%~dp0.." /Fo"%O%\\" /Fe"%O%\b3_test.exe" ^
   "%~dp0b3_continuation_test.cpp" ^
   "%S%\streaming\ContinuousExecution.cpp" ^
   "%S%\streaming\EventLedger.cpp" ^
   "%S%\AgentToolAuthority.cpp" ^
   /link /SUBSYSTEM:CONSOLE
if errorlevel 1 ( echo BUILD_FAIL & exit /b 1 )
echo BUILD=PASS
"%O%\b3_test.exe"
exit /b %errorlevel%
