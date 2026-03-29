@echo off
REM build_tests.bat - Build and run AgentHotPatcher tests on Windows
setlocal EnableExtensions EnableDelayedExpansion

REM Always run relative to this script's directory.
cd /d "%~dp0"

echo === Building AgentHotPatcher Test Suite ===

set "PROJECT_ROOT=%CD%\rawrxd"
if not exist "%PROJECT_ROOT%\CMakeLists_tests.txt" (
  echo Expected RawrXD source tree at: %PROJECT_ROOT%
  echo Missing: %PROJECT_ROOT%\CMakeLists_tests.txt
  exit /b 1
)

REM Ensure we have a VS toolchain available (cl/msbuild), otherwise CMake may default to NMake without nmake present.
if not defined VSINSTALLDIR (
  set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
  if exist "%VSWHERE%" (
    for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINSTALL=%%I"
    if defined VSINSTALL (
      if exist "%VSINSTALL%\Common7\Tools\VsDevCmd.bat" (
        call "%VSINSTALL%\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 >nul
      )
    )
  )
)

REM Create a small, dedicated CMake source tree for the test CMakeLists.
set "TEST_SRC=%CD%\build_tests_src"
set "TEST_BLD=%CD%\build_tests"

if not exist "%TEST_SRC%" mkdir "%TEST_SRC%"
REM Always start from a clean build dir to avoid CMakeCache source-dir mismatches.
if exist "%TEST_BLD%" rmdir /s /q "%TEST_BLD%"
mkdir "%TEST_BLD%"

REM Materialize CMakeLists.txt and required sources.
copy /Y "%PROJECT_ROOT%\CMakeLists_tests.txt" "%TEST_SRC%\CMakeLists.txt" >nul || (echo Failed to copy CMakeLists_tests.txt & exit /b 1)
copy /Y "%PROJECT_ROOT%\test_agent_hot_patcher.cpp" "%TEST_SRC%\test_agent_hot_patcher.cpp" >nul || (echo Missing %PROJECT_ROOT%\test_agent_hot_patcher.cpp & exit /b 1)
copy /Y "%PROJECT_ROOT%\test_agent_hot_patcher_integration.cpp" "%TEST_SRC%\test_agent_hot_patcher_integration.cpp" >nul || (echo Missing %PROJECT_ROOT%\test_agent_hot_patcher_integration.cpp & exit /b 1)

if not exist "%TEST_SRC%\src\agent" mkdir "%TEST_SRC%\src\agent"
set "AGENT_CPP="
set "AGENT_HPP="

if exist "%PROJECT_ROOT%\src\agent\agent_hot_patcher.cpp" set "AGENT_CPP=%PROJECT_ROOT%\src\agent\agent_hot_patcher.cpp"
if not defined AGENT_CPP if exist "%PROJECT_ROOT%\Full Source\src\agent\agent_hot_patcher.cpp" set "AGENT_CPP=%PROJECT_ROOT%\Full Source\src\agent\agent_hot_patcher.cpp"
if not defined AGENT_CPP (
  echo Missing agent_hot_patcher.cpp under %PROJECT_ROOT%\src\agent or %PROJECT_ROOT%\Full Source\src\agent
  exit /b 1
)

if exist "%PROJECT_ROOT%\src\agent\agent_hot_patcher.hpp" set "AGENT_HPP=%PROJECT_ROOT%\src\agent\agent_hot_patcher.hpp"
if not defined AGENT_HPP if exist "%PROJECT_ROOT%\Full Source\src\agent\agent_hot_patcher.hpp" set "AGENT_HPP=%PROJECT_ROOT%\Full Source\src\agent\agent_hot_patcher.hpp"

copy /Y "%AGENT_CPP%" "%TEST_SRC%\src\agent\agent_hot_patcher.cpp" >nul || (echo Failed to copy agent_hot_patcher.cpp & exit /b 1)
if defined AGENT_HPP copy /Y "%AGENT_HPP%" "%TEST_SRC%\src\agent\agent_hot_patcher.hpp" >nul

REM Configure with CMake
echo Configuring with CMake...
set "USE_VS=0"
where.exe msbuild.exe >nul 2>nul && set "USE_VS=1"

if "%USE_VS%"=="1" (
  cmake -S "%TEST_SRC%" -B "%TEST_BLD%" -G "Visual Studio 17 2022" -A x64
  if errorlevel 1 exit /b %errorlevel%
) else (
  where.exe ninja.exe >nul 2>nul || (echo No Visual Studio found and Ninja is not available & exit /b 1)
  where.exe g++.exe >nul 2>nul || (echo No Visual Studio found and g++ is not available & exit /b 1)
  cmake -S "%TEST_SRC%" -B "%TEST_BLD%" -G "Ninja" -DCMAKE_BUILD_TYPE=Release
  if errorlevel 1 exit /b %errorlevel%
)

REM Build the project
echo Building tests...
if "%USE_VS%"=="1" (
  cmake --build "%TEST_BLD%" --config Release
  if errorlevel 1 exit /b %errorlevel%
) else (
  cmake --build "%TEST_BLD%"
  if errorlevel 1 exit /b %errorlevel%
)

echo === Running Tests ===

REM Run via CTest so failures propagate correctly.
echo Running CTest...
if "%USE_VS%"=="1" (
  ctest --test-dir "%TEST_BLD%" -C Release --output-on-failure
  if errorlevel 1 exit /b %errorlevel%
) else (
  ctest --test-dir "%TEST_BLD%" --output-on-failure
  if errorlevel 1 exit /b %errorlevel%
)

echo === Test Suite Completed ===
exit /b 0
