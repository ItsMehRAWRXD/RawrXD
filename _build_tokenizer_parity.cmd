@echo off
REM Build the tokenizer parity harness against the freshly built production DLL
REM and regenerate tokenizer_parity.json for RAWRXD_CORE_DLL_NATIVE_E2E_001.
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 exit /b 91
cd /d F:\rawrxd
cl /nologo /EHsc /O2 /std:c++20 /W1 /DNOMINMAX /DWIN32_LEAN_AND_MEAN ^
   /I src\core\dll /I include /I build_cert\src\core\dll ^
   tools\tokenizer_parity_dll.cpp ^
   build_cert\lib\Release\RawrXDCore.lib ^
   /Fe:tmp_build_e2e\tokenizer_parity_dll.exe
if errorlevel 1 (
  echo TOK_PARITY_BUILD_FAILED
  exit /b 2
)
echo TOK_PARITY_BUILD_OK
exit /b 0
