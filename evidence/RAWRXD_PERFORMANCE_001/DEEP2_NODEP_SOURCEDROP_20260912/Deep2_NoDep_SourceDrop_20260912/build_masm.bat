@echo off
setlocal EnableExtensions
where ml64 >nul 2>nul || (echo ERROR: ml64.exe not found. Run from VS x64 Native Tools prompt.& exit /b 2)
where lib >nul 2>nul || (echo ERROR: lib.exe not found.& exit /b 2)
if not exist build mkdir build
pushd src
for %%F in (*.asm) do (
  echo [ML64] %%F
  ml64 /nologo /c /Fo"..\build\%%~nF.obj" "%%F" || (popd & exit /b 1)
)
popd
lib /nologo /OUT:build\deep2_nodep.lib build\*.obj || exit /b 1
echo PASS: build\deep2_nodep.lib
exit /b 0
