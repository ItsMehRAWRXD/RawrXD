@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 ( echo VCVARS_FAIL & exit /b 1 )
set S=%~dp0..\src
set O=%~dp0..\build_q1
if not exist "%O%" mkdir "%O%"
cl /nologo /EHsc /std:c++17 /O1 /MT /I "%S%" /Fo"%O%\\" /Fe"%O%\q1_test.exe" ^
   "%~dp0q1_gate_verifier_test.cpp" ^
   "%S%\agentmodes\RawrGateVerifier.cpp" ^
   "%S%\agentmodes\RawrReceiptValidator.cpp" ^
   "%S%\agentmodes\RawrAuditAuthority.cpp" ^
   "%S%\deep2\ReceiptAuthority.cpp" ^
   /link /SUBSYSTEM:CONSOLE bcrypt.lib
if errorlevel 1 ( echo BUILD_FAIL & exit /b 1 )
echo BUILD=PASS
"%O%\q1_test.exe"
exit /b %errorlevel%
