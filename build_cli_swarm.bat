@echo off
setlocal enabledelayedexpansion

REM Build script for SovereignCLI with Swarm support
REM Standalone build - doesn't require full CMake

echo ============================================
echo Building SovereignCLI with Swarm Command
echo ============================================
echo.

REM Set up MSVC environment
set "VCINSTALLDIR=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC"
set "VCToolsVersion=14.51.36231"
set "VCToolsInstallDir=%VCINSTALLDIR%\Tools\MSVC\%VCToolsVersion%"
set "WindowsSdkDir=C:\Program Files (x86)\Windows Kits\10"
set "WindowsSdkVersion=10.0.22621.0"

set "PATH=%VCToolsInstallDir%\bin\HostX64\x64;%PATH%"
set "LIB=%VCToolsInstallDir%\lib\x64;%WindowsSdkDir%\Lib\%WindowsSdkVersion%\ucrt\x64;%WindowsSdkDir%\Lib\%WindowsSdkVersion%\um\x64"
set "INCLUDE=%VCToolsInstallDir%\include;%WindowsSdkDir%\Include\%WindowsSdkVersion%\ucrt;%WindowsSdkDir%\Include\%WindowsSdkVersion%\um;%WindowsSdkDir%\Include\%WindowsSdkVersion%\shared"

REM Directories
set "SRCDIR=d:\rawrxd\src"
set "BUILDDIR=d:\rawrxd\build"
set "CLIDIR=%SRCDIR%\cli"
set "SWARMDIR=%SRCDIR%\swarm"

REM Include paths
set "INCLUDES=/I. /I%SRCDIR% /I%CLIDIR% /I%SWARMDIR% /I%SRCDIR%\model /I%SRCDIR%\inference /I%SRCDIR%\core /I%SRCDIR%\infinite"

REM Compiler flags
set "CFLAGS=/std:c++17 /EHsc /O2 /W3 /nologo /DMAX_PATH=260 %INCLUDES%"

echo [1/5] Compiling SovereignCLI.cpp...
cl %CFLAGS% /c %CLIDIR%\SovereignCLI.cpp /Fo:%BUILDDIR%\SovereignCLI_new.obj
if errorlevel 1 goto :error

echo [2/5] Compiling SwarmCommand.cpp...
cl %CFLAGS% /c %CLIDIR%\SwarmCommand.cpp /Fo:%BUILDDIR%\SwarmCommand.obj
if errorlevel 1 goto :error

echo [3/5] Compiling SovereignConfig.cpp...
cl %CFLAGS% /c %CLIDIR%\SovereignConfig.cpp /Fo:%BUILDDIR%\SovereignConfig_new.obj
if errorlevel 1 goto :error

echo [4/5] Compiling SovereignSwarm.cpp...
cl %CFLAGS% /c %SWARMDIR%\SovereignSwarm.cpp /Fo:%BUILDDIR%\SovereignSwarm.obj
if errorlevel 1 goto :error

echo [5/5] Linking SovereignCLI.exe...
link /OUT:%BUILDDIR%\SovereignCLI_swarm.exe %BUILDDIR%\SovereignCLI_new.obj %BUILDDIR%\SwarmCommand.obj %BUILDDIR%\SovereignConfig_new.obj %BUILDDIR%\SovereignSwarm.obj /LIBPATH:%BUILDDIR% /SUBSYSTEM:CONSOLE /nologo
if errorlevel 1 goto :error

echo.
echo ============================================
echo Build successful!
echo Output: %BUILDDIR%\SovereignCLI_swarm.exe
echo ============================================
goto :end

:error
echo.
echo ============================================
echo Build failed!
echo ============================================
exit /b 1

:end
endlocal
