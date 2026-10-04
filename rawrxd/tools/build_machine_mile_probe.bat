@echo off
REM RAWRXD_PREDICTOR_MACHINE_MILE_001 build.
REM Everything runs inside this one cmd block so the vcvars environment applies
REM to ml64 as well as cl. Running ml64 from PowerShell after a separate
REM `cmd /c vcvars` produced MASM_FAIL for every file, because the environment
REM variables never left the child cmd process.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 ( echo VCVARS_FAILED & exit /b 1 )

set ROOT=F:\~dev\rawrxd
set OUT=%ROOT%\build_machine_mile
if not exist "%OUT%" mkdir "%OUT%"

echo === assembling MASM kernels ===
for %%A in (sovereign_q4k_gemv_v2 sovereign_q4_0_gemv sovereign_q4_1_gemv sovereign_q8_0_gemv sovereign_q5_k_gemv sovereign_q6_k_gemv sovereign_fp16_gemv) do (
  ml64 /nologo /c /Fo"%OUT%\%%A.obj" "%ROOT%\src\deep2\%%A.asm" > "%OUT%\%%A.masm.log" 2>&1
  if errorlevel 1 ( echo MASM_FAIL %%A & type "%OUT%\%%A.masm.log" & exit /b 1 )
)
echo MASM_OK

echo === compiling ===
cl /nologo /std:c++20 /EHsc /W3 /O2 /MD /DNDEBUG /D_CRT_SECURE_NO_WARNINGS ^
   /I "%ROOT%\src\deep2" ^
   /Fo"%OUT%\\" /Fe"%OUT%\machine_mile_probe.exe" ^
   "%ROOT%\src\deep2\MachineMile.cpp" ^
   "%ROOT%\src\deep2\QuantKernelRegistry.cpp" ^
   "%ROOT%\tools\machine_mile_probe.cpp" ^
   /link /OUT:"%OUT%\machine_mile_probe.exe" ^
   "%OUT%\sovereign_q4k_gemv_v2.obj" ^
   "%OUT%\sovereign_q4_0_gemv.obj" ^
   "%OUT%\sovereign_q4_1_gemv.obj" ^
   "%OUT%\sovereign_q8_0_gemv.obj" ^
   "%OUT%\sovereign_q5_k_gemv.obj" ^
   "%OUT%\sovereign_q6_k_gemv.obj" ^
   "%OUT%\sovereign_fp16_gemv.obj"

if errorlevel 1 ( echo BUILD_FAILED & exit /b 1 )
echo BUILD_OK
endlocal