@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "G:\~dev\rawrxd\evidence\UNLINKED_SYMBOLS_E2E_001"
set INC=/I"G:\~dev\rawrxd" /I"G:\~dev\rawrxd\src" /I"G:\~dev\rawrxd\src\core" /I"G:\~dev\rawrxd\include"
set FAIL=0
for %%F in (unlinked_symbols_batch_001.cpp unlinked_symbols_batch_006.cpp unlinked_symbols_batch_007.cpp unlinked_symbols_batch_008.cpp unlinked_symbols_batch_009.cpp unlinked_symbols_batch_010.cpp) do (
  echo === %%F ===
  cl /nologo /c /EHsc /std:c++20 /DWIN32 /D_WIN32 /Fo%%~nF.obj %INC% "G:\~dev\rawrxd\src\core\%%F"
  if errorlevel 1 set FAIL=1
)
if %FAIL%==0 (echo SMOKE_COMPILE_OK) else (echo SMOKE_COMPILE_FAIL & exit /b 1)
