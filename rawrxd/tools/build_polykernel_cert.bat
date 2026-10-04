@echo off
REM RAWRXD_POLYKERNEL_001 — standalone build of the reverse/polykernel cert.
REM Links the REAL QuantKernelRegistry so parity is measured against the
REM production kernel, not against a local reimplementation.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 ( echo VCVARS_FAILED & exit /b 1 )

set ROOT=F:\~dev\rawrxd
set OUT=F:\~dev\rawrxd\build_polykernel_cert
if not exist "%OUT%" mkdir "%OUT%"

set MASM=sovereign_q4k_gemv_v2 sovereign_q4_0_gemv sovereign_q4_1_gemv sovereign_q8_0_gemv sovereign_q5_k_gemv sovereign_q6_k_gemv sovereign_fp16_gemv

echo === assembling MASM kernels ===
for %%A in (%MASM%) do (
  ml64 /nologo /c /Fo"%OUT%\%%A.obj" "%ROOT%\src\deep2\%%A.asm" > "%OUT%\%%A.masm.log" 2>&1
  if errorlevel 1 ( echo MASM_FAIL %%A & type "%OUT%\%%A.masm.log" & exit /b 1 )
)

echo === compiling C++ ===
REM /std:c++20 is required: TensorIdentity.hpp and ReverseLayer.hpp both use
REM defaulted comparison operators.
cl /nologo /std:c++20 /EHsc /W3 /O2 /MD /DNDEBUG /D_CRT_SECURE_NO_WARNINGS ^
   /I "%ROOT%\src\deep2" /I "%ROOT%\src" ^
   /Fo"%OUT%\\" /Fe"%OUT%\polykernel_cert.exe" ^
   "%ROOT%\src\deep2\ReverseLayer.cpp" ^
   "%ROOT%\src\deep2\HeartbeatPublisher.cpp" ^
   "%ROOT%\src\deep2\LoomPromotion.cpp" ^
   "%ROOT%\src\deep2\PolyKernelGenerator.cpp" ^
   "%ROOT%\src\deep2\QuantKernelRegistry.cpp" ^
   "%ROOT%\src\deep2\GGUFLoader.cpp" ^
   "%ROOT%\tools\polykernel_cert.cpp" ^
   /link /OUT:"%OUT%\polykernel_cert.exe" ^
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
