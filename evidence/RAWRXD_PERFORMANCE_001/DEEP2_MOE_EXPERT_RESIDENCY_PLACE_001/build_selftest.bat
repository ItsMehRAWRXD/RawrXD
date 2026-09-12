@echo off
setlocal
set ROOT=%~dp0..\..\..
set SRC1=%ROOT%\src\deep2\MoEExpertResidencyPlace.cpp
set SRC2=%ROOT%\src\deep2\MoEExpertResidencyPlace_Place.cpp
set OUT=%~dp0selftest_moe_place.exe
where cl >nul 2>&1
if errorlevel 1 (
  echo CL_NOT_FOUND
  exit /b 2
)
cl /nologo /EHsc /O2 /std:c++17 /I"%ROOT%\src\deep2" "%~dp0selftest_moe_place.cpp" "%SRC1%" "%SRC2%" /Fe"%OUT%"
if errorlevel 1 exit /b 1
"%OUT%"
exit /b %ERRORLEVEL%
