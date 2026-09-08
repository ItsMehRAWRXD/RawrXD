@echo off
REM IDE autocomplete only — not linked into Deep2.
setlocal
cd /d "%~dp0"
if not defined VSCMD_ARG_TGT_ARCH (
  call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
)
"%VCINSTALLDIR%Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe" /nologo /std:c++17 /O2 /EHsc /Fe:rawr_copilot.exe rawr_copilot_markov.cpp
if errorlevel 1 exit /b 1
if not exist bin mkdir bin
copy /Y rawr_copilot.exe bin\rawr_copilot_markov.exe >nul
echo BUILT=%CD%\rawr_copilot.exe
echo BUILT=%CD%\bin\rawr_copilot_markov.exe
endlocal
