@echo off
setlocal
where cl >nul 2>nul || (
  echo ERROR: run from a VS 2022 x64 Developer Command Prompt or call vcvars64.bat
  exit /b 2
)
if not exist build mkdir build
cl /nologo /std:c++17 /EHsc /W4 /WX /permissive- /sdl /Iinclude /c src\EnterpriseDualStickLocality.cpp /Fobuild\EnterpriseDualStickLocality.obj || exit /b 3
cl /nologo /std:c++17 /EHsc /W4 /WX /permissive- /sdl /Iinclude tests\selftest.cpp build\EnterpriseDualStickLocality.obj /Febuild\dualstick_locality_selftest.exe || exit /b 4
pushd build
 dualstick_locality_selftest.exe
set RC=%ERRORLEVEL%
popd
exit /b %RC%
