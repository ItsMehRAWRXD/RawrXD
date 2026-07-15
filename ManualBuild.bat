@echo off
setlocal EnableExtensions EnableDelayedExpansion
REM ============================================================================
REM RawrXD Manual Build Script
REM Run this from VS Developer Command Prompt
REM ============================================================================

echo ============================================================================
echo RawrXD Debug Stack - Manual Build
echo ============================================================================
echo.

REM Auto-bootstrap MSVC environment when not already initialized
where cl.exe >nul 2>&1
if errorlevel 1 (
	echo [env] cl.exe not found on PATH. Attempting to load VC environment...

		set VCVARS=
	if exist "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" (
		set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
	) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" (
		set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
	) else if exist "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvarsall.bat" (
		set "VCVARS=C:\VS2022Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
	) else if exist "D:\VS2022Enterprise\VC\Auxiliary\Build\vcvarsall.bat" (
		set "VCVARS=D:\VS2022Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
	)

	if not defined VCVARS (
		echo [error] Could not find vcvarsall.bat.
		echo [hint] Install VS C++ Build Tools or run from Developer Command Prompt.
		goto :error
	)

	echo [env] Using: !VCVARS!
	call "!VCVARS!" x64 >nul
	if errorlevel 1 (
		echo [error] Failed to initialize MSVC environment.
		goto :error
	)

	where cl.exe >nul 2>&1
	if errorlevel 1 (
		echo [error] cl.exe still unavailable after vcvarsall.
		goto :error
	)

	REM Fallback: ensure Windows SDK include/lib paths exist for windows.h resolution
	set "SDKROOT=C:\Program Files (x86)\Windows Kits\10"
	set "SDKVER="
	if exist "%SDKROOT%\Include\10.0.26100.0\um\windows.h" (
		set "SDKVER=10.0.26100.0"
	) else if exist "%SDKROOT%\Include\10.0.22621.0\um\windows.h" (
		set "SDKVER=10.0.22621.0"
	)

	if defined SDKVER (
		set "INCLUDE=%SDKROOT%\Include\!SDKVER!\ucrt;%SDKROOT%\Include\!SDKVER!\shared;%SDKROOT%\Include\!SDKVER!\um;%INCLUDE%"
		set "LIB=%SDKROOT%\Lib\!SDKVER!\ucrt\x64;%SDKROOT%\Lib\!SDKVER!\um\x64;%LIB%"
	)
)

set "SRC=d:\rawrxd\src"
set "OUT=d:\rawrxd\build\bin"
set "SDKVER="

if exist "C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um\windows.h" (
	set "SDKVER=10.0.26100.0"
) else if exist "C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um\windows.h" (
	set "SDKVER=10.0.22621.0"
)

if not exist "%OUT%" mkdir "%OUT%"

echo Building debug components...
echo Output: %OUT%
echo.

REM Compile DebugBackend
echo [1/8] DebugBackend.cpp
cl.exe /nologo /EHsc /O2 /W4 /DUNICODE /D_UNICODE /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\ucrt" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\um" /I"%SRC%\debug" /c "%SRC%\debug\DebugBackend.cpp" /Fo"%OUT%\DebugBackend.obj"
if errorlevel 1 goto :error

REM Compile DebugBridge
echo [2/8] DebugBridge.cpp
cl.exe /nologo /EHsc /O2 /W4 /DUNICODE /D_UNICODE /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\ucrt" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\um" /I"%SRC%\debug" /c "%SRC%\debug\DebugBridge.cpp" /Fo"%OUT%\DebugBridge.obj"
if errorlevel 1 goto :error

REM Compile DAPAdapter
echo [3/8] DAPAdapter.cpp
cl.exe /nologo /EHsc /O2 /W4 /DUNICODE /D_UNICODE /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\ucrt" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\um" /I"%SRC%\debug" /c "%SRC%\debug\DAPAdapter.cpp" /Fo"%OUT%\DAPAdapter.obj"
if errorlevel 1 goto :error

REM Compile DapService
echo [4/8] DapService.cpp
cl.exe /nologo /EHsc /O2 /W4 /DUNICODE /D_UNICODE /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\ucrt" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\um" /I"%SRC%\debug" /c "%SRC%\debug\DapService.cpp" /Fo"%OUT%\DapService.obj"
if errorlevel 1 goto :error

REM Compile GitHelper
echo [5/8] GitHelper.cpp
cl.exe /nologo /EHsc /O2 /W4 /DUNICODE /D_UNICODE /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\ucrt" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\um" /I"%SRC%\utils" /c "%SRC%\utils\GitHelper.cpp" /Fo"%OUT%\GitHelper.obj"
if errorlevel 1 goto :error

REM Compile StatusBarGitMonitor
echo [6/8] StatusBarGitMonitor.cpp
cl.exe /nologo /EHsc /O2 /W4 /DUNICODE /D_UNICODE /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\ucrt" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\um" /I"%SRC%\win32app" /I"%SRC%\debug" /c "%SRC%\win32app\StatusBarGitMonitor.cpp" /Fo"%OUT%\StatusBarGitMonitor.obj"
if errorlevel 1 goto :error

REM Compile DAPIntegrationBridge
echo [7/8] DAPIntegrationBridge.cpp
cl.exe /nologo /EHsc /O2 /W4 /DUNICODE /D_UNICODE /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\ucrt" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\um" /I"%SRC%\win32app" /I"%SRC%\debug" /c "%SRC%\win32app\DAPIntegrationBridge.cpp" /Fo"%OUT%\DAPIntegrationBridge.obj"
if errorlevel 1 goto :error

REM Compile BreakpointManagerPanel
echo [8/8] BreakpointManagerPanel.cpp
cl.exe /nologo /EHsc /O2 /W4 /DUNICODE /D_UNICODE /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\ucrt" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\um" /I"%SRC%\win32app" /I"%SRC%\debug" /c "%SRC%\win32app\BreakpointManagerPanel.cpp" /Fo"%OUT%\BreakpointManagerPanel.obj"
if errorlevel 1 goto :error

echo.
echo Linking executables...
echo.

REM Link QuickTest.exe
echo - QuickTest.exe
cl.exe /nologo /EHsc /O2 /W4 /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\ucrt" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\um" "%SRC%\debug\QuickTest.cpp" "%OUT%\DebugBackend.obj" "%OUT%\DebugBridge.obj" "%OUT%\GitHelper.obj" /Fe"%OUT%\QuickTest.exe" /link dbghelp.lib kernel32.lib user32.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 goto :error

REM Link VerticalTest.exe
echo - VerticalTest.exe
cl.exe /nologo /EHsc /O2 /W4 /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\ucrt" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\um" "%SRC%\debug\VerticalTest.cpp" "%OUT%\DebugBackend.obj" "%OUT%\DebugBridge.obj" "%OUT%\DAPAdapter.obj" "%OUT%\DapService.obj" /Fe"%OUT%\VerticalTest.exe" /link dbghelp.lib kernel32.lib user32.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 goto :error

REM Link DAPServer.exe
echo - DAPServer.exe
cl.exe /nologo /EHsc /O2 /W4 /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\ucrt" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\%SDKVER%\um" "%SRC%\debug\DAPServer.cpp" "%OUT%\DebugBackend.obj" "%OUT%\DebugBridge.obj" "%OUT%\DAPAdapter.obj" "%OUT%\DapService.obj" /Fe"%OUT%\DAPServer.exe" /link dbghelp.lib kernel32.lib user32.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 goto :error

echo.
echo ============================================================================
echo BUILD SUCCESSFUL
echo ============================================================================
echo.
echo Executables created:
echo   %OUT%\QuickTest.exe
echo   %OUT%\VerticalTest.exe
echo   %OUT%\DAPServer.exe
echo.
echo Run tests:
echo   %OUT%\QuickTest.exe
echo   %OUT%\VerticalTest.exe
echo.
goto :end

:error
echo.
echo ============================================================================
echo BUILD FAILED
echo ============================================================================
echo.
exit /b 1

:end
echo Done.
