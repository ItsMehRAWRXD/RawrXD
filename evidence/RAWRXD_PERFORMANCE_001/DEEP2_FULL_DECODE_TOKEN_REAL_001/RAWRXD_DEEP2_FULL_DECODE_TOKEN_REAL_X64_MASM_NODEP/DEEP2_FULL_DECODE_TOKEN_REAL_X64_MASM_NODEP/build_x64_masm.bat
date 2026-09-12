@echo off
setlocal
if "%VSCMD_ARG_TGT_ARCH%"=="" (
  echo ERROR: run from an x64 Visual Studio Developer Command Prompt.
  exit /b 2
)

if not exist build mkdir build

ml64 /nologo /c /W3 /Fo"build\deep2_full_decode_token_real.obj" deep2_full_decode_token_real.asm
if errorlevel 1 exit /b %errorlevel%

lib /nologo /OUT:"build\deep2_full_decode_token_real.lib" "build\deep2_full_decode_token_real.obj"
if errorlevel 1 exit /b %errorlevel%

echo BUILD=PASS
echo EXTERNAL_THIRD_PARTY_DEPS=0
echo OUTPUT=build\deep2_full_decode_token_real.lib
exit /b 0
