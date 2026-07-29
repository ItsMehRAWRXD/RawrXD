@echo off
REM Simple build for VAL-051.2.A

call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

set RAWRXD_ROOT=D:\rawrxd
set WINSDK_VER=10.0.22621.0

cl.exe /std:c++20 /O2 /EHsc /W3 /nologo /D_CRT_SECURE_NO_WARNINGS /DWIN32_LEAN_AND_MEAN ^
  /I"%RAWRXD_ROOT%\include" ^
  /I"%RAWRXD_ROOT%\src" ^
  /I"%RAWRXD_ROOT%\include\core" ^
  /I"C:\Program Files (x86)\Windows Kits\10\include\%WINSDK_VER%\um" ^
  /I"C:\Program Files (x86)\Windows Kits\10\include\%WINSDK_VER%\shared" ^
  /I"C:\Program Files (x86)\Windows Kits\10\include\%WINSDK_VER%\ucrt" ^
  val_051_2_a_standalone_token_proof.cpp ^
  "%RAWRXD_ROOT%\src\gguf_loader.cpp" ^
  "%RAWRXD_ROOT%\src\core\inference_witness.cpp" ^
  /Fe:val_051_2_a.exe

if %ERRORLEVEL% neq 0 (
  echo Build failed
  exit /b 1
)

echo Build SUCCESS: val_051_2_a.exe
