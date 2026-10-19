@echo off
setlocal
if "%VSCMD_ARG_TGT_ARCH%"=="" (
  echo ERROR: run from x64 VS Developer Command Prompt
  exit /b 2
)
if not exist build mkdir build
ml64 /nologo /c /W3 /Fo"build\deep2_auth_grant.obj" deep2_auth_grant.asm
if errorlevel 1 exit /b %errorlevel%
lib /nologo /OUT:"build\deep2_auth_grant.lib" "build\deep2_auth_grant.obj"
if errorlevel 1 exit /b %errorlevel%
echo BUILD=PASS OUTPUT=build\deep2_auth_grant.lib
echo OBSERVATION_MINTS_AUTHORITY=1 DECLARATION_MINTS_AUTHORITY=0
exit /b 0
