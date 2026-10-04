@echo off
REM RAWRKD_POLYKERNEL_SOURCELESS_AUTHORITY_001 cert build.
REM Links the REAL QuantKernelRegistry so parity is measured against the
REM production F32 GEMV. No MASM kernels are needed: the kernel under test is
REM machine code emitted at runtime by X64Emitter, not a prebuilt object.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 ( echo VCVARS_FAILED & exit /b 1 )

set ROOT=F:\~dev\rawrxd
set OUT=F:\~dev\rawrxd\build_polykernel_sourceless
if not exist "%OUT%" mkdir "%OUT%"

echo === compiling ===
cl /nologo /std:c++20 /EHsc /W3 /O2 /MD /DNDEBUG /D_CRT_SECURE_NO_WARNINGS ^
   /I "%ROOT%\src\deep2" ^
   /Fo"%OUT%\\" /Fe"%OUT%\polykernel_sourceless_cert.exe" ^
   "%ROOT%\src\deep2\PolyKernel.cpp" ^
   "%ROOT%\src\deep2\QuantKernelRegistry.cpp" ^
   "%ROOT%\tools\polykernel_sourceless_cert.cpp"

if errorlevel 1 ( echo BUILD_FAILED & exit /b 1 )
echo BUILD_OK
endlocal